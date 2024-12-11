# Copyright (C) 2024 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import base64
import logging
import smtplib
import textwrap

import pytest

from swh.model.swhids import ExtendedSWHID
from swh.storage.proxies.masking.db import MaskedState, MaskingAdmin

from ..notifications import RemovalNotification


@pytest.fixture
def masking_admin(masking_db_postgresql_dsn) -> MaskingAdmin:
    return MaskingAdmin.connect(masking_db_postgresql_dsn)


def test_watch_notifications(
    mocker,
    notification_journal_writer,
    example_watcher,
    example_removal_notification,
):
    notification_journal_writer.write_additions(
        "removal_notification", [example_removal_notification]
    )
    process_removal_notification = mocker.patch.object(
        example_watcher, "process_removal_notification"
    )
    example_watcher.watch()
    process_removal_notification.assert_called_once_with(example_removal_notification)


def test_process_removal_notification(
    smtpd,
    example_watcher,
    masking_admin,
    example_removal_notification,
):
    example_watcher.process_removal_notification(example_removal_notification)

    masking_requests = masking_admin.get_requests(include_cleared_requests=True)
    assert len(masking_requests) == 1
    masking_request, masked_count = masking_requests[0]
    assert masked_count == 8
    assert (
        masking_request.slug == "removal-from-main-archive-example-removal-notification"
    )
    assert "https://example.com/swh/graph" in masking_request.reason
    assert (
        "swh:1:snp:0000000000000000000000000000000000000022" in masking_request.reason
    )
    states = masking_admin.get_states_for_request(masking_request.id)
    assert all(state == MaskedState.DECISION_PENDING for state in states.values())
    assert set(states.keys()) == {
        ExtendedSWHID.from_string(s)
        for s in (
            "swh:1:ori:8f50d3f60eae370ddbf85c86219c55108a350165",
            "swh:1:snp:0000000000000000000000000000000000000022",
            "swh:1:rel:0000000000000000000000000000000000000021",
            "swh:1:rev:0000000000000000000000000000000000000018",
            "swh:1:dir:0000000000000000000000000000000000000017",
            "swh:1:cnt:0000000000000000000000000000000000000015",
            "swh:1:cnt:0000000000000000000000000000000000000014",
            "swh:1:emd:101d70c3574c1e4b730d7ba8e83a4bdadc8691cb",
        )
    }
    assert len(smtpd.messages) == 1
    assert (
        "Removal from the main Software Heritage archive (example-removal-notification)"
        in smtpd.messages[0]["Subject"]
    )


def test_process_removal_notification_no_reason(
    smtpd,
    example_watcher,
    masking_admin,
    example_removal_notification,
):
    example_removal_notification.reason = None
    example_watcher.process_removal_notification(example_removal_notification)
    assert len(smtpd.messages) == 1

    msg = smtpd.messages[0]
    assert (
        "Removal from the main Software Heritage archive (example-removal-notification)"
        in msg["Subject"]
    )
    body = base64.b64decode(msg.get_payload()).decode()
    assert (
        "removed from the main Software Heritage archive "
        "for the following reason:\n\n\n\n"
    ) in body


def test_process_removal_notification_idempotency(
    example_watcher,
    masking_admin,
    example_removal_notification,
):
    example_watcher.process_removal_notification(example_removal_notification)
    example_watcher.process_removal_notification(example_removal_notification)

    assert len(masking_admin.get_requests(include_cleared_requests=True)) == 1


def test_process_removal_notification_failure(
    mocker,
    example_watcher,
    masking_admin,
    example_removal_notification,
):
    mocker.patch(
        "swh.alter.mirror_notification_watcher.MaskingAdmin.record_history",
        side_effect=IOError,
    )

    with pytest.raises(IOError):
        example_watcher.process_removal_notification(example_removal_notification)

    assert len(masking_admin.get_requests(include_cleared_requests=True)) == 0


def test_format_removal_email(
    example_watcher,
    example_removal_notification,
):
    text = example_watcher.format_removal_email(example_removal_notification)
    print(text)
    assert (
        textwrap.dedent(
            """\
        - origin: 1
        - snapshot: 1
        - release: 1
        - revision: 1
        - directory: 1
        - content: 2
        - raw extrinsic metadata: 1
        """
        )
        in text
    )
    assert "    We need to test stuff" in text
    assert "- https://example.com/swh/graph" in text
    assert "- swh:1:snp:0000000000000000000000000000000000000022" in text


def test_format_removal_email_with_missing_requested_objects(
    example_watcher,
    example_removal_notification,
):
    notification_d = example_removal_notification.to_dict()
    notification_d["requested"].append(
        "swh:1:snp:ffffffffffffffffffffffffffffffffffffffff"
    )
    notification_d["removed_objects"].append(
        "swh:1:snp:ffffffffffffffffffffffffffffffffffffffff"
    )
    text = example_watcher.format_removal_email(
        RemovalNotification.from_dict(notification_d)
    )
    assert (
        textwrap.dedent(
            """\
        - origin: 1
        - snapshot: 2
        - release: 1
        - revision: 1
        - directory: 1
        - content: 2
        - raw extrinsic metadata: 1
        """
        )
        in text
    )
    assert "- https://example.com/swh/graph" in text
    assert "- swh:1:snp:0000000000000000000000000000000000000022" in text
    assert (
        "- swh:1:snp:ffffffffffffffffffffffffffffffffffffffff ⚠️  Missing from mirror"
        in text
    )


def test_send_upstream_removal_email_no_recipients(
    caplog,
    mocker,
    example_watcher,
    example_removal_notification,
):
    mocker.patch(
        "smtplib.SMTP.sendmail",
        side_effect=smtplib.SMTPRecipientsRefused(recipients={}),
    )
    with caplog.at_level(logging.ERROR), pytest.raises(smtplib.SMTPRecipientsRefused):
        example_watcher.send_upstream_removal_email(example_removal_notification)
    assert "No recipients were specified" in caplog.text


def test_send_upstream_removal_email_all_recipients_refused(
    caplog,
    mocker,
    example_watcher,
    example_removal_notification,
):
    mocker.patch(
        "smtplib.SMTP.sendmail",
        side_effect=smtplib.SMTPRecipientsRefused(
            recipients={"!!!": (550, b"Nope"), "???": (550, b"Neither")}
        ),
    )
    with caplog.at_level(logging.ERROR), pytest.raises(smtplib.SMTPRecipientsRefused):
        example_watcher.send_upstream_removal_email(example_removal_notification)
    assert "All recipients were refused by the SMTP server" in caplog.text
    assert "- !!!: (550) Nope" in caplog.text
    assert "- ???: (550) Neither" in caplog.text


def test_send_upstream_removal_email_some_recipient_refused(
    caplog,
    mocker,
    example_watcher,
    example_removal_notification,
):
    mocker.patch(
        "smtplib.SMTP.sendmail",
        return_value={"two@example.org": (550, b"Recipient refused")},
    )
    with caplog.at_level(logging.WARNING):
        example_watcher.send_upstream_removal_email(example_removal_notification)
    assert "Partial error when sending email" in caplog.text
    assert "Some recipients were refused by the SMTP server" in caplog.text
    assert "- two@example.org: (550) Recipient refused" in caplog.text


def test_send_upstream_removal_email_refused_sender(
    caplog,
    mocker,
    example_watcher,
    example_removal_notification,
):
    mocker.patch(
        "smtplib.SMTP.sendmail",
        side_effect=smtplib.SMTPSenderRefused(
            code=550, msg=b"Sender not allowed", sender="test@example.org"
        ),
    )
    with caplog.at_level(logging.ERROR), pytest.raises(smtplib.SMTPSenderRefused):
        example_watcher.send_upstream_removal_email(example_removal_notification)
    assert "Sender “test@example.org” was refused" in caplog.text
    assert "(550) Sender not allowed" in caplog.text


def test_send_upstream_removal_email_error_response(
    caplog,
    mocker,
    example_watcher,
    example_removal_notification,
):
    mocker.patch(
        "smtplib.SMTP.sendmail",
        side_effect=smtplib.SMTPResponseException(
            code=500, msg=b"Unrecognized command"
        ),
    )
    with caplog.at_level(logging.ERROR), pytest.raises(smtplib.SMTPResponseException):
        example_watcher.send_upstream_removal_email(example_removal_notification)
    assert "(500) Unrecognized command" in caplog.text
