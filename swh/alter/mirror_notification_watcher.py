# Copyright (C) 2024 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

from email.mime.text import MIMEText
import logging
import smtplib
import textwrap
from typing import Any, Dict, List

import yaml

from swh.journal.client import JournalClient
from swh.model.model import Origin
from swh.model.swhids import ExtendedObjectType
from swh.storage.interface import StorageInterface
from swh.storage.proxies.masking.db import DuplicateRequest, MaskedState, MaskingAdmin

from .notifications import RemovalNotification
from .utils import filter_objects_missing_from_storage

logger = logging.getLogger(__name__)

MASKING_REQUEST_IDENTIFIER_PREFIX = "removal-from-main-archive-"

REMOVAL_NOTIFICATION_RECEIVED_EMAIL_SUBJECT = """\
[Action needed] Removal from the main Software Heritage archive ({removal_identifier})\
"""

REMOVAL_NOTIFICATION_RECEIVED_EMAIL_BODY = """\
Hi!

Our mirror has received a notification that several objects were
removed from the main Software Heritage archive for the following reason:

{reason}

These objects have now been made inaccessible to the public until an action
is taken for their future on the mirror. Here are the list of objects
requested for removal:

{requested}

Number of removed objects broken down by object types:

- {origin}
- {snapshot}
- {release}
- {revision}
- {directory}
- {content}
- {raw_extrinsic_metadata}

🫵 You now need to decide between 3 options:
⚖️  Please consult your DPO/legal departement if needed.

a) Replicate the removal operation on the mirror. Objects will be
   deleted from the mirror. A recovery bundle will be created in
   case the operation needs to be reverted.

   Issue the following command:

       swh alter handle-removal-notification remove \\
         '{removal_identifier}' \\
         --recovery-bundle=/PATH/TO/RECOVERY_BUNDLE

b) Permanently restrict the access of the objects removed from the main
   archive. They will not be deleted by they will not be available to
   the public anymore.

   Issue the following command:

       swh alter handle-removal-notification restrict-permanently \\
         '{removal_identifier}'

c) Dismiss the notification. The access restriction on objects removed
   from the main archive will be lifted.

   Issue the following command:

       swh alter handle-removal-notification dismiss \\
         '{removal_identifier}'

Thank you,
--\x20
Your main archive notification monitor
"""


class MirrorNotificationWatcher:
    """Watch the journal for notifications from the main archive.

    For removal notifications, we mask the associated objects until
    a decision is made by the mirror operators.
    """

    def __init__(
        self,
        storage: StorageInterface,
        journal_client: JournalClient,
        masking_admin_dsn: str,
        emails_from: str,
        emails_recipients: List[str],
        smtp_host: str,
        smtp_port: int,
    ):
        """Instantiate a MirrorNotificationWatcher

        As notification will not be frequent, we only keep the configuration
        for MaskingAdmin instead of instantiating an object, as it would
        mean keeping a useless connection open to the database.
        """

        self._storage = storage
        self._journal_client = journal_client
        self._masking_admin_dsn = masking_admin_dsn
        self._emails_from = emails_from
        self._emails_recipients = emails_recipients
        self._smtp_host = smtp_host
        self._smtp_port = smtp_port

    def process_messages(self, messages: Dict[str, List[Dict[str, Any]]]) -> None:
        for d in messages["removal_notification"]:
            self.process_removal_notification(RemovalNotification.from_dict(d))

    def process_removal_notification(self, notification: RemovalNotification) -> None:
        # Raising an exception is the only way to prevent JournalClient from
        # committing the message offset. So in case of trouble, we do that to
        # give us a chance to process the notification again. Maybe next time
        # it’ll work as the SMTP server is back online?
        # Note the exception in question will be raised by the call to
        # self.send_upstream_removal_email()

        logger.info(
            "Received a removal notification “%s”", notification.removal_identifier
        )
        masking_admin = MaskingAdmin.connect(self._masking_admin_dsn)
        # We do want to do a proper atomic transaction here
        masking_admin.conn.autocommit = False
        masking_request_slug = (
            f"{MASKING_REQUEST_IDENTIFIER_PREFIX}{notification.removal_identifier}"
        )
        try:
            with masking_admin.conn:
                info = {
                    "reason": notification.reason,
                    "requested": [
                        obj.url if isinstance(obj, Origin) else str(obj)
                        for obj in notification.requested
                    ],
                }

                # This will fail is the notification has already been handled
                # (in case we are replaying old journal messages)
                masking_request = masking_admin.create_request(
                    masking_request_slug,
                    "Removal notification received from main archive "
                    f"({notification.removal_identifier})\n\n"
                    "---\n"
                    f"{yaml.dump(info)}",
                )
                masking_admin.set_object_state(
                    masking_request.id,
                    MaskedState.DECISION_PENDING,
                    notification.removed_objects,
                )
                masking_admin.record_history(
                    masking_request.id,
                    "Mask all objects listed in the notification until a decision is made.",
                )
                self.send_upstream_removal_email(notification)
        except DuplicateRequest:
            # We assume this means we are replaying journal messages that we
            # have already processed, and therefore, do nothing.
            logger.warning(
                "Skipping removal notification “%s”: there is already a "
                "masking request “%s” in the masking proxy database. Are "
                "we replaying old journal messages?",
                notification.removal_identifier,
                masking_request_slug,
            )
        # We wait until the transaction has been completed before logging
        logger.info(
            "%s objects have been masked until a decision is made.",
            len(notification.removed_objects),
        )

    def watch(self) -> None:
        logger.info("Watching notifications for mirrors…")
        try:
            self._journal_client.process(self.process_messages)
        finally:
            logger.info("Done watching notifications for mirrors.")
            # Usually this is never reached but for tests we have `on_eof="stop"`
            self._journal_client.close()

    def format_removal_email(self, notification) -> str:
        reason = textwrap.fill(
            notification.reason or "",
            width=68,
            initial_indent="    ",
            subsequent_indent="    ",
            break_long_words=False,
            drop_whitespace=False,
            break_on_hyphens=False,
        )
        requested_labels = {}
        for origin_or_swhid in notification.requested:
            if isinstance(origin_or_swhid, Origin):
                origin = origin_or_swhid
                requested_labels[origin.swhid()] = f"- {origin.url}"
            else:
                swhid = origin_or_swhid
                requested_labels[swhid] = f"- {str(swhid)}"
        existing_swhids = filter_objects_missing_from_storage(
            self._storage, requested_labels.keys()
        )
        for swhid in set(requested_labels.keys()) - set(existing_swhids):
            requested_labels[swhid] += " ⚠️  Missing from mirror"
        requested = "\n".join(requested_labels.values())

        breakdown = {}
        for object_type in ExtendedObjectType:
            objs = [
                obj
                for obj in notification.removed_objects
                if obj.object_type == object_type
            ]
            breakdown[object_type.name.lower()] = (
                f"{object_type.name.lower().replace('_', ' ')}: {len(objs)}"
            )
        return REMOVAL_NOTIFICATION_RECEIVED_EMAIL_BODY.format(
            removal_identifier=notification.removal_identifier,
            object_count=len(notification.removed_objects),
            reason=reason,
            requested=requested,
            **breakdown,
        )

    def send_upstream_removal_email(self, notification: RemovalNotification) -> None:
        msg = MIMEText(self.format_removal_email(notification))
        msg["From"] = self._emails_from
        msg["To"] = ", ".join(self._emails_recipients)
        msg["Subject"] = REMOVAL_NOTIFICATION_RECEIVED_EMAIL_SUBJECT.format(
            removal_identifier=notification.removal_identifier
        )
        self._smtp_send(self._emails_from, self._emails_recipients, msg)

    def _smtp_send(self, sender: str, recipients: List[str], msg: MIMEText):
        with smtplib.SMTP(host=self._smtp_host, port=self._smtp_port) as smtp_client:
            logger.debug(
                "Sending email “%s” to %s", msg["Subject"], ", ".join(recipients)
            )
            try:
                # Send the message
                refused = smtp_client.sendmail(sender, recipients, msg.as_string())
                if len(refused) > 0:
                    warning_lines = [
                        f"Partial error when sending email “{msg['Subject']}”: "
                        "Some recipients were refused by the SMTP server!"
                    ]
                    for recipient, smtp_error in refused.items():
                        smtp_code, smtp_message = smtp_error
                        warning_lines.append(
                            f"- {recipient}: ({smtp_code}) "
                            f"{smtp_message.decode('utf-8', errors='replace')}"
                        )
                    logger.warning("\n".join(warning_lines))
            except smtplib.SMTPSenderRefused as exc:
                error_message = (
                    f"Unable to send email “{msg['Subject']}”: "
                    f"Sender “{exc.sender}” was refused: "
                    f"({exc.smtp_code}) "
                    f"{exc.smtp_error.decode('utf-8', errors='replace')}"
                )
                logger.error(error_message)
                raise
            except smtplib.SMTPRecipientsRefused as exc:
                error_lines = [f"Unable to send email “{msg['Subject']}”."]
                if len(exc.recipients) == 0:
                    error_lines.append("No recipients were specified!")
                elif len(exc.recipients) == 1:
                    error_lines.append("Recipient was refused by the SMTP server:")
                else:
                    error_lines.append(
                        "All recipients were refused by the SMTP server:"
                    )
                for recipient, smtp_error in exc.recipients.items():
                    smtp_code, smtp_message = smtp_error
                    error_lines.append(
                        f"- {recipient}: ({smtp_code}) "
                        f"{smtp_message.decode('utf-8', errors='replace')}"
                    )
                logger.error("\n".join(error_lines))
                raise
            except smtplib.SMTPResponseException as exc:
                exc_error = (
                    exc.smtp_error
                    if isinstance(exc.smtp_error, str)
                    else exc.smtp_error.decode("utf-8", errors="replace")
                )
                error_message = (
                    f"Unable to send email “{msg['Subject']}”. "
                    f"Server replied: ({exc.smtp_code}) {exc_error}"
                )
                logger.error(error_message)
                raise
            except smtplib.SMTPException as exc:
                error_message = f"Unable to send email “{msg['Subject']}”."
                logger.error(error_message, exc_info=exc)
                raise
