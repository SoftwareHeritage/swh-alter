# Copyright (C) 2023 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

from __future__ import annotations

import logging
import pathlib
import sys
from typing import (
    TYPE_CHECKING,
    Callable,
    Dict,
    Iterable,
    Optional,
    Set,
    TextIO,
    Tuple,
    cast,
)

import click

from swh.core.cli import CONTEXT_SETTINGS
from swh.core.cli import swh as swh_cli_group

if TYPE_CHECKING:
    from swh.model.model import Origin
    from swh.model.swhids import ExtendedSWHID

    from .operations import Remover
    from .progressbar import ProgressBar, V
    from .recovery_bundle import ObjectDecryptionKeyProvider, ShareDecryptionKeys


class SWHIDType(click.ParamType):
    name = "swhid"

    def convert(self, value, param, ctx) -> "ExtendedSWHID":
        from swh.model.swhids import ExtendedSWHID, ValidationError

        try:
            return ExtendedSWHID.from_string(value)
        except ValidationError:
            raise click.ClickException(f"Unable to parse “{value}” as a SWHID.")


class SwhidOrUrlParamType(click.ParamType):
    name = "swhid or origin URL"

    def convert(self, value, param, ctx):
        from swh.model.exceptions import ValidationError
        from swh.model.model import Origin
        from swh.model.swhids import ExtendedSWHID

        if value.startswith("swh:1:"):
            try:
                return ExtendedSWHID.from_string(value)
            except ValidationError:
                self.fail(f"expected extended SWHID, got {value!r}", param, ctx)
        else:
            return Origin(url=value)


class ClickLoggingHandler(logging.Handler):
    """Handler displaying logs using click.secho(), passing the style extra
    attribute."""

    def emit(self, record):
        if hasattr(record, "style"):
            click.secho(self.format(record), **record.style)
        else:
            click.echo(self.format(record))


def progressbar(
    iterable: Optional[Iterable[V]] = None,
    length: Optional[int] = None,
    label: Optional[str] = None,
    show_eta: bool = True,
    show_pos: bool = False,
    show_percent: Optional[bool] = None,
    item_show_func: Optional[Callable[[V], str]] = None,
) -> ProgressBar[V]:
    bar = click.progressbar(
        iterable=iterable,
        length=length,
        label=label,
        show_eta=show_eta,
        show_pos=show_pos,
        show_percent=show_percent,
        item_show_func=item_show_func,
        file=sys.stderr,
    )
    # We have to use `cast()` to renconcile the case where
    # length is used and `click.progressbar()` returns a
    # `ProgressBar[int]`. But in that case, iterable is not
    # given, so V is not bound and it is safe to assume
    # that V = int.
    return cast("ProgressBar[V]", bar)


@swh_cli_group.group(name="alter", context_settings=CONTEXT_SETTINGS)
@click.pass_context
def alter_cli_group(ctx):
    """Archive alteration tools.

    Location of the configuration should be specified through the environment
    variable ``SWH_CONFIG_FILENAME``.

    Expected config format:

        \b
        storage:
          cls: remote
          url: https://storage-cassandra-ro.softwareheritage.org
        \b
        graph:
          url: "http://granet.internal.softwareheritage.org:5009/graph"
        \b
        restoration_storage:
          cls: remote
          url: https://storage-rw.softwareheritage.org
        \b
        removal_searches:
          main:
            cls: elasticsearch
            hosts:
            - elasticsearch:9200
        \b
        removal_storages:
          old_primary:
            cls: postgresql
            db: "service=swh"
          new_primary:
            cls: cassandra
            hosts:
            - cassandra-seed
            keyspace: swh
        \b
        removal_objstorages:
          main:
            cls: remote
            url: https://objstorage.softwareheritage.org
        \b
        removal_journals:
          main_journal:
            cls: kafka
            brokers:
            - kafka1.internal.softwareheritage.org
            prefix: swh.journal.objects
            client_id: swh.alter.removals
        \b
        recovery_bundles:
          secret_sharing:
            minimum_required_groups: 2
            groups:
              legal:
                minimum_required_shares: 1
                recipient_keys:
                    "YubiKey serial 4245067 slot 1": age1yubikey1q2e37f74zzazz75mtggzql3at66pegemfnul0dtd7axctahljkvsqezscaq
                    "YubiKey serial 2284622 slot 3": age1yubikey4o1aypv83isatti92q1zasv1hkpuozlkoak4zd66t7poud23rftqrcszjgul
              sysadmins:
                minimum_required_shares: 1
                recipient_keys:
                    "YubiKey serial 3862152 slot 1": age1yubikeyrupnxsu6uneqxw146g9szaofyxexiy4nhnzqg1ayb9b85g8h4oardwj6c212
                    "Ruby": age1y6epp27nq8n4faj8g8hkw8thcvj744y5vnr8jyfmp4857d6npc3qn9k7jz
        \b
        journal_writer:
          cls: kafka
          brokers:
          - kafka1.internal.softwareheritage.org
          prefix: swh.journal
          client_id: swh.alter.removals

    The identifier for the recipient key must be in the form of
    “YubiKey serial ####### slot #” if the secret key is stored
    on a YubiKey. Keys specified by any other identifiers will be
    considered as plain age identities.
    """  # noqa: B950
    from swh.core import config

    from .operations import logger as operations_logger
    from .recovery_bundle import logger as recovery_bundle_logger

    try:
        conf = config.load_from_envvar()
    except AssertionError as ex:
        raise click.ClickException(ex.args[0])
    ctx.ensure_object(dict)
    ctx.obj["config"] = conf

    for logger in (operations_logger, recovery_bundle_logger):
        if not logger.propagate:
            # Avoid configuring the logger twice
            continue
        logger.propagate = False
        logger.addHandler(ClickLoggingHandler())

    return ctx


def read_swhids(file: TextIO) -> Set["ExtendedSWHID"]:
    import re

    from swh.model.swhids import ExtendedSWHID

    filter_re = re.compile(r"^(#|$)")
    return {
        ExtendedSWHID.from_string(line.strip())
        for line in file.read().split("\n")
        if not filter_re.match(line)
    }


def get_remover(
    ctx: click.Context,
    dry_run: bool = False,
    require_masking_admin: bool = False,
    ignore_backends: Optional[Iterable[str]] = None,
) -> "Remover":
    from psycopg2 import OperationalError, ProgrammingError

    from swh.core.api import RemoteException
    from swh.graph.http_client import GraphAPIError, RemoteGraphClient
    from swh.journal.writer import get_journal_writer
    from swh.journal.writer.kafka import KafkaJournalWriter
    from swh.objstorage.factory import get_objstorage
    from swh.objstorage.interface import ObjStorageInterface
    from swh.search import get_search
    from swh.search.interface import SearchInterface
    from swh.storage import get_storage
    from swh.storage.interface import ObjectDeletionInterface

    from .operations import Remover

    conf = ctx.obj["config"]
    if ignore_backends is None:
        ignore_backends = []

    if "graph" not in conf:
        if "graph" in ignore_backends:
            graph_client = None
        else:
            raise click.ClickException("Configuration does not define `graph`")
    else:
        try:
            graph_client = RemoteGraphClient(**conf["graph"])
        except GraphAPIError as e:
            raise click.ClickException(
                f"Unable to connect to the graph server: {e.args}"
            )

    storage = get_storage(**conf["storage"])

    if not dry_run:
        if "restoration_storage" not in conf:
            raise click.ClickException(
                "Configuration does not define `restoration_storage`"
            )
        if "search" not in ignore_backends and (
            "removal_searches" not in conf or len(conf["removal_searches"]) == 0
        ):
            raise click.ClickException(
                "Configuration does not define any `removal_searches`"
            )
        if "removal_storages" not in conf or len(conf["removal_storages"]) == 0:
            raise click.ClickException(
                "Configuration does not define any `removal_storages`"
            )
        if "removal_objstorages" not in conf or len(conf["removal_objstorages"]) == 0:
            raise click.ClickException(
                "Configuration does not define any `removal_objstorages`"
            )
        if "journal" not in ignore_backends and (
            "removal_journals" not in conf or len(conf["removal_journals"]) == 0
        ):
            raise click.ClickException(
                "Configuration does not define any `removal_journals`"
            )

    restoration_storage = (
        get_storage(**conf["restoration_storage"])
        if "restoration_storage" in conf
        else None
    )

    removal_searches = {}
    for name, d in conf.get("removal_searches", {}).items():
        removal_searches[name] = get_search(**d)
        try:
            removal_searches[name].check()
        except RemoteException as e:
            raise click.ClickException(f"Search “{name}” is unreachable: {e}")

    removal_storages = {}
    for name, d in conf.get("removal_storages", {}).items():
        removal_storage = get_storage(**d)
        assert hasattr(
            removal_storage, "object_delete"
        ), f"storage “{name}” does not implement ObjectDeletionInterface"
        removal_storages[name] = removal_storage

    removal_objstorages = {}
    for name, d in conf.get("removal_objstorages", {}).items():
        removal_objstorages[name] = get_objstorage(**d)

    removal_journals = {}
    for name, d in conf.get("removal_journals", {}).items():
        journal_writer = get_journal_writer(**d)
        assert isinstance(
            journal_writer, KafkaJournalWriter
        ), "journal writer is not kafka-based"
        removal_journals[name] = journal_writer

    known_missing = set(ctx.params.get("known_missing_swhids", set()))
    if known_missing_file := ctx.params.get("known_missing_file"):
        known_missing.update(read_swhids(known_missing_file))

    if require_masking_admin:
        from swh.storage.proxies.masking.db import MaskingAdmin

        if "masking_admin" not in conf or "db" not in conf["masking_admin"]:
            raise click.ClickException("masking_admin.db not found in configuration")
        try:
            masking_admin = MaskingAdmin.connect(conf["masking_admin"]["db"])
        except (OperationalError, ProgrammingError) as e:
            raise click.ClickException(f"Unable to connect to masking database: {e}")
    else:
        masking_admin = None

    return Remover(
        storage=storage,
        graph_client=graph_client,
        restoration_storage=restoration_storage,
        removal_searches=cast(Dict[str, SearchInterface], removal_searches),
        removal_storages=cast(Dict[str, ObjectDeletionInterface], removal_storages),
        removal_objstorages=cast(Dict[str, ObjStorageInterface], removal_objstorages),
        removal_journals=cast(Dict[str, KafkaJournalWriter], removal_journals),
        masking_admin=masking_admin,
        known_missing=known_missing,
        progressbar=progressbar,
    )


@alter_cli_group.command()
@click.option(
    "--dry-run",
    type=click.Choice(
        ["stop-before-recovery-bundle", "stop-before-removal"], case_sensitive=False
    ),
    help="perform a trial run",
)
@click.option(
    "--output-inventory-subgraph",
    type=click.File(mode="w", atomic=True),
)
@click.option(
    "--output-removable-subgraph",
    type=click.File(mode="w", atomic=True),
)
@click.option(
    "--output-pruned-removable-subgraph",
    type=click.File(mode="w", atomic=True),
)
@click.option(
    "--identifier",
    metavar="IDENTIFIER",
    required=True,
    help="identifier for this removal operation",
)
@click.option(
    "--reason",
    metavar="REASON",
    help="reason for this removal operation",
)
@click.option(
    "--expire",
    metavar="YYYY-MM-DD",
    type=click.DateTime(formats=["%Y-%m-%d"]),
    help="date when the recovery bundle should be removed",
)
@click.option(
    "--recovery-bundle",
    metavar="PATH",
    type=click.Path(dir_okay=False),
    required=True,
    help="path to the recovery bundle that will be created",
)
@click.option(
    "--known-missing",
    "known_missing_swhids",
    metavar="SWHID",
    type=SWHIDType(),
    multiple=True,
    help="object known to be missing from storage",
)
@click.option(
    "--known-missing-file",
    "known_missing_file",
    metavar="PATH",
    type=click.File(),
    help=(
        "file (or '-') with object known to be missing from storage, "
        "one SWHID per line"
    ),
)
@click.option(
    "--allow-empty-content-objects/--disallow-empty-content-objects",
    "allow_empty_content_objects",
    default=False,
    help="Create recovery bundle even when data for Content object cannot be found",
)
@click.option(
    "--ignore",
    "ignore_backends",
    default=None,
    multiple=True,
    type=click.Choice(["search", "journal", "graph"], case_sensitive=False),
    help=(
        "Do not make the given backend mandatory when checking the configuration; "
        "this command is usually meant to remove objects from all possible data silos, "
        "so the default behavior is to have all of them mandatory in the configuration "
        "file. Using this option allows to explicitly ignore the given 'backend'"
    ),
)
@click.argument(
    "requested",
    metavar="<SWHID|URL>..",
    type=SwhidOrUrlParamType(),
    required=True,
    nargs=-1,
)
@click.pass_context
def remove(
    ctx,
    requested: Tuple["Origin" | "ExtendedSWHID", ...],
    dry_run: bool,
    output_inventory_subgraph,
    output_removable_subgraph,
    output_pruned_removable_subgraph,
    identifier,
    reason,
    expire,
    recovery_bundle,
    known_missing_swhids,
    known_missing_file,
    allow_empty_content_objects,
    ignore_backends,
) -> None:
    """Remove the given SWHIDs or URLs from the archive."""

    from swh.journal.writer import JournalWriterInterface, get_journal_writer
    from swh.model.model import Origin

    from .inventory import RootsNotFound, StuckInventoryException
    from .notifications import RemovalNotification
    from .operations import RemoverError
    from .recovery_bundle import ContentDataNotFound, SecretSharing

    try:
        secret_sharing = SecretSharing.from_dict(
            ctx.obj["config"]["recovery_bundles"]["secret_sharing"]
        )
    except ValueError as e:
        raise click.ClickException(f"Wrong secret sharing configuration: {e.args[0]}")

    if dry_run != "stop-before-recovery-bundle":
        try:
            p = pathlib.Path(recovery_bundle)
            p.touch(exist_ok=False)
            p.unlink()
        except FileExistsError:
            raise click.ClickException(f"File “{recovery_bundle}” already exists")
        except PermissionError:
            raise click.ClickException(f"Permission denied: “{recovery_bundle}”")

    remover = get_remover(ctx, dry_run, ignore_backends=ignore_backends)

    swhids = [x.swhid() if isinstance(x, Origin) else x for x in requested]

    journal_writer: Optional[JournalWriterInterface] = None
    if "journal_writer" in ctx.obj["config"]:
        cfg = ctx.obj["config"]["journal_writer"]
        journal_writer = get_journal_writer(**cfg)

    try:
        removable = remover.get_removable(
            swhids,
            output_inventory_subgraph=output_inventory_subgraph,
            output_removable_subgraph=output_removable_subgraph,
            output_pruned_removable_subgraph=output_pruned_removable_subgraph,
        )
        removable.print_plan()
        if dry_run == "stop-before-recovery-bundle":
            click.echo("Stopping before creating the recovery bundle as requested.")
            ctx.exit(0)

        if dry_run is None:
            click.confirm(
                click.style(
                    "Proceed?",
                    fg="yellow",
                    bold=True,
                ),
                abort=True,
            )

        decryption_key = remover.create_recovery_bundle(
            secret_sharing=secret_sharing,
            requested=list(requested),
            removable=removable,
            recovery_bundle_path=recovery_bundle,
            removal_identifier=identifier,
            reason=reason,
            expire=expire.astimezone() if expire else None,
            allow_empty_content_objects=allow_empty_content_objects,
        )
        click.secho(f"Recovery bundle decryption key: {decryption_key}", fg="blue")
    except RemoverError as e:
        click.secho(e.args[0], err=True, fg="red")
        ctx.exit(1)
    except RootsNotFound as e:
        click.secho(
            "Some requested objects were not found:",
            err=True,
            fg="red",
            bold=True,
        )
        for label in e.get_labels(requested):
            click.secho(f"- {label}", err=True)
        ctx.exit(1)
    except StuckInventoryException as e:
        click.secho(
            "Inventory phase got stuck. "
            "Unable to learn the complete set of what these objects reference:",
            err=True,
            fg="red",
            bold=True,
        )
        click.secho("\n".join(f"- {swhid}" for swhid in e.swhids), err=True, fg="red")
        ctx.exit(1)
    except ContentDataNotFound as e:
        click.secho(
            f"Content “{e.swhid}” exists, but its data was not found.",
            err=True,
            fg="red",
            bold=True,
        )
        click.secho(
            "Consider using `--allow-empty-content-objects` but only "
            "if the above is expected.",
            err=True,
            fg="yellow",
        )
        ctx.exit(1)

    if dry_run == "stop-before-removal":
        click.echo("Stopping before removal.")
        ctx.exit(0)

    try:
        remover.remove()
    except Exception as e:
        click.secho(str(e), err=True, fg="red", bold=True)
        click.secho("Rolling back…", fg="cyan")
        remover.restore_recovery_bundle()
        ctx.exit(1)
    else:
        if journal_writer is not None:
            click.secho("Sending removal notification…", fg="cyan")
            notif = RemovalNotification(
                removal_identifier=identifier,
                reason=reason,
                requested=list(swhids),
                removed_objects=remover.swhids_to_remove,
            )
            journal_writer.write_addition("removal_notification", notif)
            journal_writer.flush()
            click.secho("Removal notification sent.", fg="green")


@alter_cli_group.command("list-candidates")
@click.option(
    "--omit-referenced/--no-omit-referenced",
    default=True,
    help="Omit candidates that are referenced by other objects",
)
@click.argument(
    "requested",
    metavar="<SWHID|URL>..",
    type=SwhidOrUrlParamType(),
    required=True,
    nargs=-1,
)
@click.pass_context
def list_candidates(
    ctx: click.Context,
    requested: Tuple["Origin" | "ExtendedSWHID", ...],
    omit_referenced: bool,
):
    """List candidates for an altering operation (e.g. removal)

    Display a list of SWHIDs of objects that would be affected by an altering
    operation targeting the SWHIDs (or origin URLs) given as arguments.

    Candidates referenced by objects in the graph outside the set of candidates
    will be filtered out, unless `--no-omit-referenced` is given.
    """

    from swh.graph.http_client import GraphAPIError, RemoteGraphClient
    from swh.model.model import Origin
    from swh.storage import get_storage

    from .inventory import (
        RootsNotFound,
        StuckInventoryException,
        get_raw_extrinsic_metadata,
        make_inventory,
    )
    from .removable import mark_removable

    conf = ctx.obj["config"]

    try:
        graph_client = RemoteGraphClient(**conf["graph"])
    except GraphAPIError as e:
        raise click.ClickException(f"Unable to connect to the graph server: {e.args}")

    storage = get_storage(**conf["storage"])

    swhids = [x.swhid() if isinstance(x, Origin) else x for x in requested]
    try:
        subgraph = make_inventory(
            storage, graph_client, swhids, progressbar=progressbar
        )
    except StuckInventoryException as e:
        click.secho(
            "Inventory phase got stuck. "
            "Unable to learn the complete set of what these objects reference:",
            err=True,
            fg="red",
            bold=True,
        )
        click.secho("\n".join(f"- {swhid}" for swhid in e.swhids), err=True, fg="red")
        ctx.exit(1)
    except RootsNotFound as e:
        click.secho(
            "Some requested objects were not found:",
            err=True,
            fg="red",
            bold=True,
        )
        for label in e.get_labels(requested):
            click.secho(f"- {label}", err=True)
        ctx.exit(1)
    if omit_referenced:
        subgraph = mark_removable(
            storage, graph_client, subgraph, progressbar=progressbar
        )
        subgraph.delete_unremovable()
    removable_swhids = list(subgraph.swhids())
    removable_swhids.extend(
        get_raw_extrinsic_metadata(storage, removable_swhids, progressbar=progressbar)
    )
    for swhid in removable_swhids:
        click.echo(swhid)


@alter_cli_group.command("run-mirror-notification-watcher")
@click.pass_context
def run_mirror_notification_watcher(ctx: click.Context):
    """Watch the journal for notifications from the main archive.

    For removal notifications, we mask the associated objects until
    a decision is made by the mirror operators.

    Example configuration:

        \b
        journal_client:
          brokers: kafka.example.org:9092
          group_id: mirror-notification-watcher
          prefix: swh.journal
        storage:
          cls: remote
          url: https://storage-ro
        masking_admin:
          cls: postgresql
          db: service=masking-db-rw
        emails:
          from: swh-mirror@example.org
          recipients:
          - trinity@example.org
          - neo@example.org
        smtp:
          host: localhost
          port: 25

    The addresses listed as “recipients” in the “emails” section will receive
    an email to let them know that a decision needs to be taken.
    """

    from swh.alter.mirror_notification_watcher import MirrorNotificationWatcher
    from swh.journal.client import get_journal_client
    from swh.storage import get_storage
    from swh.storage.proxies.masking.db import MaskingAdmin

    conf = ctx.obj["config"]

    try:
        storage = get_storage(**conf["storage"])
        storage.check_config(check_write=False)
    except Exception as e:
        raise click.ClickException(f"Unable to query to the storage: {e}")

    try:
        journal_client = get_journal_client(
            **{
                **conf["journal_client"],
                "cls": "kafka",
                "object_types": ["removal_notification"],
            }
        )
    except Exception as e:
        raise click.ClickException(f"Unable to setup the journal client: {repr(e)}")

    try:
        masking_admin_dsn = conf["masking_admin"]["db"]
        _ = MaskingAdmin.connect(masking_admin_dsn)
    except Exception as e:
        raise click.ClickException(
            f"Unable to connect to the masking proxy database: {repr(e)}"
        )

    emails_from = conf["emails"].get("from")
    if emails_from is None:
        raise click.ClickException("“emails.from” has not been set.")
    emails_recipients = conf["emails"].get("recipients")
    if emails_recipients is None:
        raise click.ClickException("“emails.recipients” has not been set.")
    if not isinstance(emails_recipients, list) or len(emails_recipients) < 1:
        raise click.ClickException(
            "“emails.recipients” must be a list and contain at least one email address."
        )

    smtp_host = conf["smtp"].get("host")
    if smtp_host is None:
        raise click.ClickException("“smtp.host” has not been set.")
    try:
        smtp_port = int(conf["smtp"].get("port"))
    except Exception as e:
        raise click.ClickException(f"“smtp.port” must be set to a port number: {e}")

    watcher = MirrorNotificationWatcher(
        storage=storage,
        journal_client=journal_client,
        masking_admin_dsn=masking_admin_dsn,
        emails_from=emails_from,
        emails_recipients=emails_recipients,
        smtp_host=smtp_host,
        smtp_port=smtp_port,
    )
    try:
        watcher.watch()
    except KeyboardInterrupt:
        ctx.exit(0)


@alter_cli_group.group(name="recovery-bundle", context_settings=CONTEXT_SETTINGS)
@click.pass_context
def recovery_bundle_cli_group(ctx):
    """Recovery bundle related tools."""
    return ctx


@recovery_bundle_cli_group.command(name="info")
@click.option(
    "--dump-manifest",
    is_flag=True,
    default=False,
    help="Show raw manifest in YAML format.",
)
@click.option(
    "--show-encrypted-secrets",
    is_flag=True,
    default=False,
    help="Show encrypted secrets.",
)
@click.argument(
    "recovery-bundle",
    type=click.Path(exists=True, dir_okay=False, readable=True),
    required=True,
)
@click.pass_context
def info(ctx, recovery_bundle, dump_manifest, show_encrypted_secrets) -> None:
    """Display the manifest of the given recovery bundle."""
    from swh.model.model import Origin

    from .recovery_bundle import RecoveryBundle

    bundle = RecoveryBundle(recovery_bundle)

    if dump_manifest:
        click.echo(bundle.dump_manifest(), nl=False)
        ctx.exit()

    title = f"Recovery bundle “{bundle.removal_identifier}”"
    click.echo(title)
    click.echo("=" * len(title))
    click.echo("")
    click.echo(f"Created: {bundle.created.isoformat()}")
    if bundle.reason:
        lines = bundle.reason.rstrip().split("\n")
        lines[0] = f"Reason: {lines[0]}"
        click.echo("\n        ".join(lines))
    if bundle.expire:
        click.echo(f"Expire: {bundle.expire}")
    if bundle.version >= 3:
        click.echo("Removal requested for:")
        for x in bundle.requested:
            click.echo(f"- {x.url if isinstance(x, Origin) else x}")
    click.echo("SWHID of the objects present in the bundle:")
    for swhid in bundle.swhids:
        click.echo(f"- {swhid}")
    if bundle.version >= 3 and len(bundle.referencing):
        click.echo("SWHID referenced by objects in this bundle:")
        for swhid in bundle.referencing:
            click.echo(f"- {swhid}")
    click.echo("Secret share holders:")
    for share_id in sorted(bundle.share_ids):
        click.echo(f"- {share_id}")
        if show_encrypted_secrets:
            click.echo(bundle.encrypted_secret(share_id))


def _share_decryption_keys_provider(share_ids: Set[str]) -> ShareDecryptionKeys:
    import subprocess
    import sys

    from .recovery_bundle import list_yubikey_identities

    for attempt in range(1, 10):
        if not any(share_id.startswith("YubiKey") for share_id in share_ids):
            # No shares require a YubiKey, so there is nothing we can do here
            break
        try:
            for share_id, secret_key in list_yubikey_identities():
                if share_id not in share_ids:
                    continue
                share_ids.remove(share_id)
                click.echo(
                    "🔧 Decrypting share using "
                    f"{click.style(share_id, fg='magenta', bold=True)}…"
                )
                click.echo("💭 You might need to tap the right YubiKey when it blinks.")
                yield share_id, secret_key
                click.echo()
        except subprocess.CalledProcessError as ex:
            if "age-plugin-yubikey" not in ex.cmd[0]:
                raise
            click.echo(
                f"""💥 {click.style('age-plugin-yubikey failed to '
                                    'list connected YubiKeys.', bold=True, fg='red')}"""
            )
            click.echo("💭 Please disconnect all YubiKeys and retry.")
            sys.exit(1)
        if share_ids:
            yubikey_ids = list(sorted(share_ids))
            if len(yubikey_ids) > 1:
                yubikeys = ", ".join(
                    click.style(share_id, fg="magenta", bold=True)
                    for share_id in yubikey_ids[:-1]
                )
                yubikeys += " or " + click.style(
                    yubikey_ids[-1], fg="magenta", bold=True
                )
            else:
                yubikeys = click.style(yubikey_ids[0], fg="magenta", bold=True)
            click.prompt(
                f"🔐 Please insert {yubikeys} and press "
                f"{click.style('Enter', fg='green', bold=True)}…",
                default="Ok",
                show_default=False,
                hide_input=True,
                prompt_suffix="",
            )
    click.echo(
        f"""💥 {click.style('Unable to decrypt enough shared secrets to recover '
                                   'the object decryption key. Aborting.',
                                   bold=True, fg='red')}"""
    )
    sys.exit(1)


def _print_decrypted_mnemonic(mnemonic: str, share_id: Optional[str] = None) -> None:
    fmt_from = ""
    if share_id:
        fmt_from = f" from {click.style(share_id, fg='magenta', bold=True)}"
    click.echo(f"🔑 Recovered shared secret{fmt_from}:")
    # Quoting from SLIP-0039: This construction yields a beneficial
    # property where the random identifier and the iteration exponent
    # transform into the first two words of the mnemonic code, so the user
    # can immediately tell whether the correct shares are being combined,
    # i.e. they have to have the same first two words. Moreover, the third
    # word encodes the group index, group threshold and part of the group
    # count. Since the group threshold and group count are constant, all
    # **shares belonging to the same group start with the same three words**.
    words = mnemonic.split()
    click.echo(
        " ".join(
            click.style(word, fg="blue", bold=index < 3)
            for index, word in enumerate(words)
        )
    )


def _recover_mnemonics_from_identity_files(
    manifest, share_ids, identity_files, show_decrypted_mnemonics
):
    from .recovery_bundle import WrongDecryptionKey, age_decrypt_from_identity

    # As we can’t know which identity file corresponds to which encrypted shared
    # secret, we have to try them all and see which one we can actually decrypt.
    recovered = {}
    for identity_file in identity_files:
        for share_id in share_ids:
            try:
                recovered[share_id] = age_decrypt_from_identity(
                    identity_file, manifest.decryption_key_shares[share_id]
                ).decode("us-ascii")
                if show_decrypted_mnemonics:
                    _print_decrypted_mnemonic(recovered[share_id], share_id)
            except WrongDecryptionKey:
                pass
    return recovered


def prompting_object_decryption_key_provider(
    manifest, known_mnemonics=None, identity_files=None, show_decrypted_mnemonics=False
) -> str:
    import functools

    from .recovery_bundle import recover_object_decryption_key_from_encrypted_shares

    decrypted_mnemonic_processor = None
    if show_decrypted_mnemonics:
        decrypted_mnemonic_processor = _print_decrypted_mnemonic
    share_ids = set(manifest.decryption_key_shares.keys())
    # Normalize known_mnemonics
    known_mnemonics = list(known_mnemonics or [])
    if identity_files:
        recovered = _recover_mnemonics_from_identity_files(
            manifest, share_ids, identity_files, show_decrypted_mnemonics
        )
        share_ids.difference_update(recovered.keys())
        known_mnemonics.extend(recovered.values())
    yubikey_share_ids = set(
        share_id for share_id in share_ids if share_id.startswith("YubiKey")
    )
    missing_ids = share_ids - yubikey_share_ids
    if missing_ids:
        fmt_ids = ", ".join(
            click.style(share_id, fg="magenta", bold=True) for share_id in missing_ids
        )
        click.echo(
            f"""\n🚸 {click.style('The following secret shares will not be '
                                    'decrypted:', fg='yellow')} {fmt_ids}\n"""
        )

    return recover_object_decryption_key_from_encrypted_shares(
        manifest.decryption_key_shares,
        functools.partial(_share_decryption_keys_provider, yubikey_share_ids),
        decrypted_mnemonic_processor=decrypted_mnemonic_processor,
        known_mnemonics=known_mnemonics,
    )


def get_object_decryption_key_provider(ctx) -> ObjectDecryptionKeyProvider:
    import functools

    secrets = ctx.params.get("secret")
    identity_files = ctx.params.get("identity")
    object_decryption_key_provider: ObjectDecryptionKeyProvider = functools.partial(
        prompting_object_decryption_key_provider,
        known_mnemonics=secrets,
        identity_files=identity_files,
    )
    decryption_key = ctx.params.get("decryption_key")
    if decryption_key:
        if not decryption_key.lower().startswith("age-secret-key-"):
            ctx.fail(
                "The given decryption key does not look like a decryption key. "
                "It should start with “AGE-SECRET-KEY-”"
            )

        def known_key_provider(_):
            return decryption_key

        object_decryption_key_provider = known_key_provider
    return object_decryption_key_provider


class ContentSWHID(click.ParamType):
    name = "swhid of a content object"

    def convert(self, value, param, ctx):
        from swh.model.swhids import ExtendedObjectType, ExtendedSWHID, ValidationError

        try:
            swhid = ExtendedSWHID.from_string(value)
        except ValidationError:
            self.fail(f"expected SWHID, got {value!r}", param, ctx)
        if swhid.object_type != ExtendedObjectType.CONTENT:
            self.fail("We can only extract data for Content objects", param, ctx)
        return swhid


@recovery_bundle_cli_group.command(name="extract-content")
@click.option(
    "-o",
    "--output",
    type=click.File("wb"),
    metavar="FILE",
    required=True,
    help="write data to FILE",
)
@click.option(
    "--decryption-key",
    metavar="AGE_SECRET_KEY",
    help="use the given decryption key instead of the bundle shared secrets",
)
@click.option(
    "-s",
    "--secret",
    metavar="MNEMONIC",
    multiple=True,
    help="Known shared secret. May be repeated.",
)
@click.option(
    "-i",
    "--identity",
    metavar="IDENTITY",
    type=click.Path(exists=True, readable=True, dir_okay=False),
    multiple=True,
    help="Path to file with age identities. May be repeated.",
)
@click.argument(
    "recovery-bundle",
    type=click.Path(exists=True, dir_okay=False, readable=True),
    required=True,
)
@click.argument(
    "SWHID",
    type=ContentSWHID(),
    required=True,
)
@click.pass_context
def extract_content(
    ctx,
    output,
    recovery_bundle,
    swhid,
    decryption_key=None,
    identity=None,
    secret=None,
) -> None:
    """Extract data from content stored in a recovery bundle."""
    from .recovery_bundle import RecoveryBundle, WrongDecryptionKey

    secret_key_provider = get_object_decryption_key_provider(ctx)
    bundle = RecoveryBundle(recovery_bundle, secret_key_provider)

    if swhid not in bundle.swhids:
        click.secho(
            f"“{swhid}” is not in the recovery bundle", err=True, fg="red", bold=True
        )
        ctx.exit(1)

    try:
        bundle.write_content_data(swhid, output)
    except WrongDecryptionKey:
        click.secho(
            f"Wrong decryption key for this bundle ({bundle.removal_identifier})",
            err=True,
            fg="red",
            bold=True,
        )
        ctx.exit(2)


@recovery_bundle_cli_group.command(name="restore")
@click.option(
    "--decryption-key",
    metavar="AGE_SECRET_KEY",
    help="use the given decryption key instead of the bundle shared secrets",
)
@click.option(
    "-s",
    "--secret",
    metavar="MNEMONIC",
    multiple=True,
    help="Known shared secret. May be repeated.",
)
@click.option(
    "-i",
    "--identity",
    metavar="IDENTITY",
    type=click.Path(exists=True, readable=True, dir_okay=False),
    multiple=True,
    help="Path to file with age identities. May be repeated.",
)
@click.argument(
    "recovery-bundle",
    type=click.Path(exists=True, dir_okay=False, readable=True),
    required=True,
)
@click.pass_context
def restore(
    ctx, recovery_bundle, decryption_key=None, identity=None, secret=None
) -> None:
    """Restore a recovery bundle to Software Heritage archive."""
    from .recovery_bundle import (
        RecoveryBundle,
        UnsupportedFeatureException,
        WrongDecryptionKey,
    )

    conf = ctx.obj["config"]
    from swh.storage import get_storage

    restoration_storage = get_storage(**conf["restoration_storage"])

    secret_key_provider = get_object_decryption_key_provider(ctx)
    bundle = RecoveryBundle(recovery_bundle, secret_key_provider)
    try:
        missing = bundle.get_missing_referenced_objects(restoration_storage)
        if len(missing) > 0:
            click.secho(
                "Objects to be restored are referencing objects that "
                "are missing from storage:",
                fg="yellow",
                bold=True,
            )
            for swhid in missing:
                click.secho(f"- {swhid}", fg="yellow")
            click.confirm(
                click.style(
                    "Proceed with restoration though it will create "
                    "references to missing objects?",
                    fg="yellow",
                    bold=True,
                ),
                abort=True,
            )
    except UnsupportedFeatureException:
        click.secho(
            "Skipping checks for missing referenced objects: "
            f"recovery bundle “{recovery_bundle}” is too old.",
            fg="yellow",
            bold=True,
        )
    try:
        bundle.restore(restoration_storage, progressbar)
    except WrongDecryptionKey:
        click.echo(
            f"Wrong decryption key for this bundle ({bundle.removal_identifier})"
        )
        ctx.exit(2)


@recovery_bundle_cli_group.command(name="resume-removal")
@click.option(
    "--decryption-key",
    metavar="AGE_SECRET_KEY",
    prompt=True,
    help="use the given decryption key instead of the bundle shared secrets",
    envvar="SWH_BUNDLE_DECRYPTION_KEY",
)
@click.argument(
    "recovery-bundle",
    type=click.Path(exists=True, dir_okay=False, readable=True),
    required=True,
)
@click.pass_context
def resume_removal(
    ctx,
    recovery_bundle,
    decryption_key=None,
) -> None:
    """Resume a removal operation from a recovery bundle."""
    from swh.journal.writer import JournalWriterInterface, get_journal_writer

    from .notifications import RemovalNotification
    from .recovery_bundle import WrongDecryptionKey

    remover = get_remover(ctx)
    journal_writer: Optional[JournalWriterInterface] = None
    if "journal_writer" in ctx.obj["config"]:
        cfg = ctx.obj["config"]["journal_writer"]
        journal_writer = get_journal_writer(**cfg)

    try:
        bundle = remover.register_objects_from_bundle(
            recovery_bundle_path=recovery_bundle, object_secret_key=decryption_key
        )
    except WrongDecryptionKey:
        click.echo("Wrong decryption key for this bundle")
        ctx.exit(2)
    try:
        remover.remove()
    except Exception as e:
        click.secho(str(e), err=True, fg="red", bold=True)
        remover.restore_recovery_bundle()
        ctx.exit(1)
    else:
        if journal_writer is not None:
            notif = RemovalNotification(
                removal_identifier=bundle.removal_identifier,
                reason=bundle.reason or "",
                requested=bundle.requested,
                removed_objects=remover.swhids_to_remove,
            )
            journal_writer.write_addition("removal_notification", notif)
            journal_writer.flush()


def _strip_rage_report(output):
    # rage prompts for report when it errors like this:
    #   [ Did rage not do what you expected? Could an error be more useful? ]
    #   [ Tell us: https://str4d.xyz/rage/report                            ]
    # This can be confusing in our case so strip them from the output.
    return b"\n".join(
        line
        for line in output.split(b"\n")
        if not line.startswith(b"[") and not line.endswith(b"]")
    )


@recovery_bundle_cli_group.command(name="recover-decryption-key")
@click.option(
    "-s",
    "--secret",
    metavar="MNEMONIC",
    multiple=True,
    help="Known shared secret. May be repeated.",
)
@click.option(
    "-i",
    "--identity",
    metavar="IDENTITY",
    type=click.Path(exists=True, readable=True, dir_okay=False),
    multiple=True,
    help="Path to file with age identities. May be repeated.",
)
@click.option(
    "--show-recovered-secrets",
    is_flag=True,
    default=False,
    help="Show recovered shared secrets. Useful for remote/distributed recoveries.",
)
@click.argument(
    "recovery-bundle",
    type=click.Path(exists=True, dir_okay=False, readable=True),
    required=True,
)
def recover_decryption_key(
    recovery_bundle, secret, identity, show_recovered_secrets
) -> None:
    """Recover the decryption key using shared secrets."""
    import subprocess
    import sys

    from .recovery_bundle import RecoveryBundle

    def object_decryption_key_provider(*args, **kwargs):
        kwargs["known_mnemonics"] = list(secret)
        kwargs["identity_files"] = list(identity)
        kwargs["show_decrypted_mnemonics"] = show_recovered_secrets
        return prompting_object_decryption_key_provider(*args, **kwargs)

    try:
        bundle = RecoveryBundle(recovery_bundle, object_decryption_key_provider)
        decryption_key = bundle.object_decryption_key
        click.echo(
            f"\n🔓 Recovered decryption key:\n{click.style(decryption_key, bold=True)}"
        )
    except subprocess.CalledProcessError as ex:
        if "rage" not in ex.cmd[0] and ex.cmd[1] != "--decrypt":
            raise
        click.echo(
            f"""💥 {click.style('rage decryption failed:', bold=True, fg='red')}"""
        )
        click.echo(_strip_rage_report(ex.stderr))
        sys.exit(1)


@recovery_bundle_cli_group.command(name="rollover")
@click.option(
    "--decryption-key",
    metavar="AGE_SECRET_KEY",
    help="use the given decryption key instead of the bundle shared secrets",
)
@click.option(
    "-s",
    "--secret",
    metavar="MNEMONIC",
    multiple=True,
    help="Known shared secret. May be repeated.",
)
@click.option(
    "-i",
    "--identity",
    metavar="IDENTITY",
    type=click.Path(exists=True, readable=True, dir_okay=False),
    multiple=True,
    help="Path to file with age identities. May be repeated.",
)
@click.argument(
    "recovery-bundles",
    metavar="[RECOVERY_BUNDLE]…",
    type=click.Path(exists=True, dir_okay=False, readable=True),
    nargs=-1,
)
@click.pass_context
def rollover(
    ctx, recovery_bundles, decryption_key=None, identity=None, secret=None
) -> None:
    """Rollover recovery bundles to new shared secrets."""
    conf = ctx.obj["config"]

    from .recovery_bundle import RecoveryBundle, SecretSharing, WrongDecryptionKey

    secret_key_provider = get_object_decryption_key_provider(ctx)
    secret_sharing = SecretSharing.from_dict(conf["recovery_bundles"]["secret_sharing"])
    click.secho("New shared secret holders:")
    for share_id in sorted(secret_sharing.share_ids):
        click.echo(f"- {click.style(share_id, fg='magenta', bold=True)}")
    click.confirm(
        click.style(
            "Proceed with rolling over the shared secrets?",
            fg="yellow",
            bold=True,
        ),
        abort=True,
    )
    for recovery_bundle in recovery_bundles:
        bundle = RecoveryBundle(recovery_bundle, secret_key_provider)
        # Ensure that we can decrypt at least some objects with the provided key
        try:
            origin = list(bundle.origins())
            assert len(origin) > 0, "Oops! No Origin objects in this recovery bundle."
        except WrongDecryptionKey:
            click.secho(
                f"Wrong decryption key for this bundle ({bundle.removal_identifier})",
                err=True,
                fg="red",
                bold=True,
            )
            ctx.exit(2)
        bundle.rollover(secret_sharing)
        click.secho("Shared secrets for ", fg="green", nl=False)
        click.secho(bundle.removal_identifier, fg="green", bold=True, nl=False)
        click.secho(" have been rolled over.", fg="green")


@alter_cli_group.group(
    name="handle-removal-notification", context_settings=CONTEXT_SETTINGS
)
@click.pass_context
def handle_removal_notification_cli_group(ctx):
    """Tools to handle removal notifications."""
    return ctx


@handle_removal_notification_cli_group.command(name="remove")
@click.option(
    "--recovery-bundle",
    type=click.Path(dir_okay=False),
    required=True,
)
@click.option(
    "--allow-empty-content-objects/--disallow-empty-content-objects",
    "allow_empty_content_objects",
    default=False,
    help="Create recovery bundle even when data for Content object cannot be found",
)
@click.option(
    "--ignore-requested",
    "ignore_requested",
    metavar="ORIGIN_OR_SWHID",
    multiple=True,
    type=SwhidOrUrlParamType(),
    help="object that should be ignored from the list of "
    "requested objects to be removed",
)
@click.option(
    "--ignore",
    "ignore_backends",
    default=None,
    multiple=True,
    type=click.Choice(["search", "journal", "graph"], case_sensitive=False),
    help=(
        "Do not make the given backend mandatory when checking the configuration; "
        "this command is usually meant to remove objects from all possible data silos, "
        "so the default behavior is to have all of them mandatory in the configuration "
        "file. Using this option allows to explicitly ignore the given 'backend'"
    ),
)
@click.option(
    "--recompute/--no-recompute",
    default=False,
    help=(
        "If set, recompute locally the list of swhids to remove to apply "
        "the given removal request, otherwise, use the list of swhids "
        "sent in the notification message. Note that an access to swh-graph "
        "is required to reocmpute this list. Implies '--ignore graph' if not set."
    ),
)
@click.argument(
    "removal-identifier",
    required=True,
)
@click.pass_context
def handle_removal_notification_with_removal(
    ctx,
    recovery_bundle,
    removal_identifier,
    allow_empty_content_objects,
    ignore_requested,
    ignore_backends,
    recompute,
):
    """Handle removal notification by removing the request objects."""

    from .inventory import RootsNotFound, StuckInventoryException
    from .operations import MaskingRequestNotFound, RemoverError
    from .recovery_bundle import ContentDataNotFound, SecretSharing

    ignore_backends = set(ignore_backends or [])

    if recompute:
        ignore_backends.discard("graph")
    else:
        ignore_backends.add("graph")

    remover = get_remover(
        ctx,
        require_masking_admin=True,
        ignore_backends=ignore_backends,
    )

    try:
        secret_sharing = SecretSharing.from_dict(
            ctx.obj["config"]["recovery_bundles"]["secret_sharing"]
        )
    except ValueError as e:
        raise click.ClickException(f"Wrong secret sharing configuration: {e.args[0]}")

    try:
        p = pathlib.Path(recovery_bundle)
        p.touch(exist_ok=False)
        p.unlink()
    except FileExistsError:
        raise click.ClickException(f"File “{recovery_bundle}” already exists")
    except PermissionError:
        raise click.ClickException(f"Permission denied: “{recovery_bundle}”")

    try:
        remover.handle_removal_notification_with_removal(
            notification_removal_identifier=removal_identifier,
            secret_sharing=secret_sharing,
            recovery_bundle_path=recovery_bundle,
            ignore_requested=ignore_requested or [],
            allow_empty_content_objects=allow_empty_content_objects,
            recompute_swhids_to_remove=recompute,
        )
    except MaskingRequestNotFound as e:
        click.secho(
            f"Masking request “{e.masking_request_slug}” has not been found.",
            err=True,
            fg="red",
        )
        click.secho(
            f"Please double-check that “{removal_identifier}” is the identifier of "
            "the notification. Otherwise, there probably was an error with the "
            "processing of the notification."
        )
        ctx.exit(1)
    except RootsNotFound:
        # handle_removal_notification_with_removal() has already
        # displayed the missing objects
        click.secho(
            "You might want to use “--ignore-requested=https://…” "
            "to specify which requested object should be ignored.",
            err=True,
            fg="yellow",
            bold="True",
        )
        ctx.exit(1)
    except StuckInventoryException as e:
        click.secho(
            "Inventory phase got stuck. "
            "Unable to learn the complete set of what these objects reference:",
            err=True,
            fg="red",
            bold=True,
        )
        click.secho("\n".join(f"- {swhid}" for swhid in e.swhids), err=True, fg="red")
        ctx.exit(1)
    except ContentDataNotFound as e:
        click.secho(
            f"Content “{e.swhid}” exists, but its data was not found.",
            err=True,
            fg="red",
            bold=True,
        )
        click.secho(
            "Consider using `--allow-empty-content-objects` but only "
            "if the above is expected.",
            err=True,
            fg="yellow",
        )
        ctx.exit(1)
    except RemoverError:
        # Showing the exception and rolling back has been handled by
        # handle_removal_notification_with_removal()
        ctx.exit(1)
    except Exception as e:
        raise e


@handle_removal_notification_cli_group.command(name="restrict-permanently")
@click.argument(
    "removal-identifier",
    required=True,
)
@click.pass_context
def handle_removal_notification_with_permanent_restriction(
    ctx,
    removal_identifier,
):
    """Handle removal notification by permanently restricting access
    to objects removed from the main archive."""

    from swh.storage.proxies.masking.db import MaskedState

    from .operations import MaskingRequestNotFound

    remover = get_remover(
        ctx, require_masking_admin=True, ignore_backends=["graph", "search", "journal"]
    )

    try:
        remover.handle_removal_notification_by_changing_masked_status(
            notification_removal_identifier=removal_identifier,
            masked_state=MaskedState.RESTRICTED,
        )
    except MaskingRequestNotFound as e:
        click.secho(
            f"Masking request “{e.masking_request_slug}” has not been found.",
            err=True,
            fg="red",
        )
        click.secho(
            f"Please double-check that “{removal_identifier}” is the identifier of "
            "the notification. Otherwise, there probably was an error with the "
            "processing of the notification."
        )
        ctx.exit(1)
    click.secho(
        f"Removal notification “{removal_identifier}” handled by "
        "permanently restricting access to the objects removed from the main archive.",
        fg="green",
        bold=True,
    )


@handle_removal_notification_cli_group.command(name="dismiss")
@click.argument(
    "removal-identifier",
    required=True,
)
@click.pass_context
def handle_removal_notification_with_dismissal(
    ctx,
    removal_identifier,
):
    """Handle removal notification by making the objects removed from the
    main archive visible again."""

    from swh.storage.proxies.masking.db import MaskedState

    from .operations import MaskingRequestNotFound

    remover = get_remover(
        ctx, require_masking_admin=True, ignore_backends=["graph", "search", "journal"]
    )

    try:
        remover.handle_removal_notification_by_changing_masked_status(
            notification_removal_identifier=removal_identifier,
            masked_state=MaskedState.VISIBLE,
        )
    except MaskingRequestNotFound as e:
        click.secho(
            f"Masking request “{e.masking_request_slug}” has not been found.",
            err=True,
            fg="red",
        )
        click.secho(
            f"Please double-check that “{removal_identifier}” is the identifier of "
            "the notification. Otherwise, there probably was an error with the "
            "processing of the notification."
        )
        ctx.exit(1)
    click.secho(
        f"Removal notification “{removal_identifier}” has been dismissed: "
        "objects removed from the main archive are now visible again.",
        fg="green",
        bold=True,
    )
