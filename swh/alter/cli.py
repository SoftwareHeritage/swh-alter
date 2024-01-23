# Copyright (C) 2023 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Dict, List, Optional, Set, cast

import click

from swh.core.cli import CONTEXT_SETTINGS
from swh.core.cli import swh as swh_cli_group

if TYPE_CHECKING:
    from swh.model.swhids import ExtendedSWHID

    from .recovery_bundle import ObjectDecryptionKeyProvider, ShareDecryptionKeys


class SwhidOrUrlParamType(click.ParamType):
    name = "swhid or origin URL"

    def convert(self, value, param, ctx):
        import hashlib

        from swh.model.exceptions import ValidationError
        from swh.model.swhids import ExtendedSWHID

        if value.startswith("swh:1:"):
            try:
                return ExtendedSWHID.from_string(value)
            except ValidationError:
                self.fail(f"expected extended SWHID, got {value!r}", param, ctx)
        else:
            click.secho(f"Assuming {value} is an origin URL.", fg="cyan")
            sha1 = hashlib.sha1(value.encode("utf-8")).hexdigest()
            swhid = ExtendedSWHID.from_string(f"swh:1:ori:{sha1}")
            return swhid


class ClickLoggingHandler(logging.Handler):
    """Handler displaying logs using click.secho(), passing the style extra
    attribute."""

    def emit(self, record):
        if hasattr(record, "style"):
            click.secho(self.format(record), **record.style)
        else:
            click.echo(self.format(record))


DEFAULT_CONFIG = {
    "storage": {
        "cls": "postgresql",
        "db": "dbname=softwareheritage host=db.internal.softwareheritage.org user=guest",
        "objstorage": {
            "cls": "memory",
        },
    },
    "graph": {
        "url": "http://granet.internal.softwareheritage.org:5009/graph",
        # timeout is in seconds
        # see https://requests.readthedocs.io/en/latest/user/advanced/#timeouts
        "timeout": 10,
    },
    "recovery_bundles": {
        "secret_sharing": {
            "minimum_required_groups": 2,
            "groups": {},
        }
    },
}


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

    The identifier for the recipient key must be in the form of
    “YubiKey serial ####### slot #” if the secret key is stored
    on a YubiKey. Keys specified by any other identifiers will be
    considered as plain age identities.
    """  # noqa: B950
    from swh.core import config

    conf = config.load_from_envvar(default_config=DEFAULT_CONFIG)
    ctx.ensure_object(dict)
    ctx.obj["config"] = conf
    return ctx


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
    type=click.Path(writable=True, dir_okay=False),
    required=True,
    help="path to the recovery bundle that will be created",
)
@click.argument(
    "swhids",
    metavar="<SWHID|URL>..",
    type=SwhidOrUrlParamType(),
    required=True,
    nargs=-1,
)
@click.pass_context
def remove(
    ctx,
    swhids: List["ExtendedSWHID"],
    dry_run: bool,
    output_inventory_subgraph,
    output_removable_subgraph,
    output_pruned_removable_subgraph,
    identifier,
    reason,
    expire,
    recovery_bundle,
) -> None:
    """Remove the given SWHIDs or URLs from the archive."""
    from swh.graph.http_client import GraphAPIError, RemoteGraphClient
    from swh.journal.writer import get_journal_writer
    from swh.journal.writer.kafka import KafkaJournalWriter
    from swh.objstorage.factory import get_objstorage
    from swh.objstorage.interface import ObjStorageInterface
    from swh.storage import get_storage
    from swh.storage.interface import ObjectDeletionInterface

    from .operations import Remover, RemoverError, logger
    from .recovery_bundle import SecretSharing

    logger.propagate = False
    logger.addHandler(ClickLoggingHandler())
    logger.setLevel(logging.INFO)

    conf = ctx.obj["config"]

    try:
        graph_client = RemoteGraphClient(**conf["graph"])
    except GraphAPIError as e:
        raise click.ClickException(f"Unable to connect to the graph server: {e.args}")

    storage = get_storage(**conf["storage"])

    if not dry_run:
        if "restoration_storage" not in conf:
            raise click.ClickException(
                "Configuration does not define `restoration_storage`"
            )
        if "removal_storages" not in conf or len(conf["removal_storages"]) == 0:
            raise click.ClickException(
                "Configuration does not define any `removal_storages`"
            )
        if "removal_objstorages" not in conf or len(conf["removal_objstorages"]) == 0:
            raise click.ClickException(
                "Configuration does not define any `removal_objstorages`"
            )
        if "removal_journals" not in conf or len(conf["removal_journals"]) == 0:
            raise click.ClickException(
                "Configuration does not define any `removal_journals`"
            )

    restoration_storage = (
        get_storage(**conf["restoration_storage"])
        if "restoration_storage" in conf
        else None
    )

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

    try:
        secret_sharing = SecretSharing.from_dict(
            conf["recovery_bundles"]["secret_sharing"]
        )
    except ValueError as e:
        raise click.ClickException(f"Wrong secret sharing configuration: {e.args[0]}")

    remover = Remover(
        storage=storage,
        graph_client=graph_client,
        restoration_storage=restoration_storage,
        removal_storages=cast(Dict[str, ObjectDeletionInterface], removal_storages),
        removal_objstorages=cast(Dict[str, ObjStorageInterface], removal_objstorages),
        removal_journals=cast(Dict[str, KafkaJournalWriter], removal_journals),
    )
    try:
        removable_swhids = remover.get_removable(
            swhids,
            output_inventory_subgraph=output_inventory_subgraph,
            output_removable_subgraph=output_removable_subgraph,
            output_pruned_removable_subgraph=output_pruned_removable_subgraph,
        )
        if dry_run == "stop-before-recovery-bundle":
            click.echo(f"We would remove {len(removable_swhids)} objects:")
            for swhid in removable_swhids:
                click.echo(f" - {swhid}")
            ctx.exit(0)

        if dry_run is None:
            click.confirm(
                click.style(
                    f"Proceed with removing {len(removable_swhids)} SWHIDs?",
                    fg="yellow",
                    bold=True,
                ),
                abort=True,
            )

        remover.create_recovery_bundle(
            secret_sharing=secret_sharing,
            removable_swhids=removable_swhids,
            recovery_bundle_path=recovery_bundle,
            removal_identifier=identifier,
            reason=reason,
            expire=expire.astimezone() if expire else None,
        )
    except RemoverError as e:
        click.secho(e.args[0], err=True, fg="red")
        ctx.exit(1)

    if dry_run == "stop-before-removal":
        click.echo("Stopping before removal.")
        ctx.exit(0)

    try:
        remover.remove()
    except Exception as e:
        click.secho(str(e), err=True, fg="red", bold=True)
        remover.restore_recovery_bundle()
        ctx.exit(1)


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
    click.echo("List of SWHID objects:")
    for swhid in bundle.swhids:
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

    if str(swhid) not in bundle.swhids:
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
    from .recovery_bundle import RecoveryBundle, WrongDecryptionKey

    conf = ctx.obj["config"]
    from swh.storage import get_storage

    restoration_storage = get_storage(**conf["restoration_storage"])

    secret_key_provider = get_object_decryption_key_provider(ctx)
    bundle = RecoveryBundle(recovery_bundle, secret_key_provider)
    try:
        # XXX: we could use click.progressbar here
        results = bundle.restore(restoration_storage)
    except WrongDecryptionKey:
        click.echo(
            f"Wrong decryption key for this bundle ({bundle.removal_identifier})"
        )
        ctx.exit(2)

    click.echo(
        "Restoration complete. Results: \n"
        f"- Content objects added: {results['content:add']}\n"
        f"- Total bytes added to objstorage: {results['content:add:bytes']}\n"
        f"- SkippedContent objects added: {results['skipped_content:add']}\n"
        f"- Directory objects added: {results['directory:add']}\n"
        f"- Revision objects added: {results['revision:add']}\n"
        f"- Release objects added: {results['release:add']}\n"
        f"- Snapshot objects added: {results['snapshot:add']}\n"
        f"- Origin objects added: {results['origin:add']}\n"
    )


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
