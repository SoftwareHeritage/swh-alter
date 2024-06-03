# Copyright (C) 2023 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import collections
import contextlib
from datetime import datetime, timezone
import itertools
import logging
import operator
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile
import typing
from typing import (
    Any,
    BinaryIO,
    Callable,
    Dict,
    Iterable,
    Iterator,
    List,
    Optional,
    Sequence,
    Set,
    TextIO,
    Tuple,
    Type,
    Union,
)
from zipfile import ZipFile

import attrs
import shamir_mnemonic
from typing_extensions import Self
import yaml

from swh.core.api.classes import stream_results
from swh.core.utils import grouper
from swh.journal.serializers import kafka_to_value, value_to_kafka
from swh.model.model import (
    BaseModel,
    Content,
    Directory,
    ExtID,
    Origin,
    OriginVisit,
    OriginVisitStatus,
    RawExtrinsicMetadata,
    Release,
    Revision,
    SkippedContent,
    Snapshot,
)
from swh.model.swhids import ExtendedObjectType, ExtendedSWHID
from swh.model.swhids import ObjectType as CoreSWHIDObjectType
import swh.storage.algos.directory
import swh.storage.algos.snapshot
from swh.storage.interface import HashDict, StorageInterface

from .bech32 import Encoding as Bech32Encoding
from .bech32 import bech32_decode, bech32_encode, convert_bits
from .progressbar import ProgressBar, ProgressBarInit, no_progressbar
from .utils import iter_swhids_grouped_by_type

logger = logging.getLogger(__name__)

RAGE_PATH = shutil.which("rage")
RAGE_KEYGEN_PATH = shutil.which("rage-keygen")

if RAGE_PATH is None:
    raise ImportError("`rage` not found in path")
if RAGE_KEYGEN_PATH is None:
    raise ImportError("`rage-keygen` not found in path")

RECOVERY_BUNDLE_RESTORE_CHUNK_SIZE = 200

logger = logging.getLogger(__name__)


class _ManifestDumper(yaml.SafeDumper):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.add_representer(str, self._represent_str)
        self.add_representer(datetime, self._represent_datetime)
        self.add_representer(ExtendedSWHID, self._represent_swhid)

    def _represent_str(self, dumper, data):
        if "\n" in data:
            return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")
        return dumper.represent_scalar("tag:yaml.org,2002:str", data)

    def _represent_datetime(self, dumper, data):
        return dumper.represent_scalar(
            "tag:yaml.org,2002:timestamp", data.isoformat(timespec="seconds")
        )

    def _represent_swhid(self, dumper, data):
        return dumper.represent_scalar("tag:yaml.org,2002:str", str(data), style="")


def check_call(command: Sequence[str], **kwargs) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(command, capture_output=True, check=True, **kwargs)
    except subprocess.CalledProcessError as e:
        logger.warning(
            "Command `%s` failed with exit code %s", shlex.join(command), e.returncode
        )
        for line in e.stderr.strip().splitlines():
            logger.warning(" stderr: %s", line.strip())

        raise e


@attrs.define
class Manifest:
    version: int = attrs.field(
        validator=[
            attrs.validators.instance_of(int),
            attrs.validators.ge(1),
            attrs.validators.le(2),
        ]
    )
    removal_identifier: str = attrs.field(validator=[attrs.validators.instance_of(str)])
    created: datetime = attrs.field(validator=attrs.validators.instance_of(datetime))
    swhids: List[str] = attrs.field(validator=attrs.validators.instance_of(list))

    @swhids.validator
    def _ensure_swhids_type(self, attribute, value):
        if not all(isinstance(swhid, str) for swhid in value):
            raise ValueError("“swhids” must be a list of string")

    decryption_key_shares: Dict[str, str] = attrs.field(
        validator=[attrs.validators.instance_of(dict), attrs.validators.min_len(2)]
    )
    reason: Optional[str] = attrs.field(
        default=None,
        validator=attrs.validators.optional(attrs.validators.instance_of(str)),
    )
    expire: Optional[datetime] = attrs.field(
        default=None,
        validator=attrs.validators.optional(attrs.validators.instance_of(datetime)),
    )

    def dump(self, stream: Optional[TextIO] = None) -> Optional[str]:
        d = attrs.asdict(self)
        for optionals in ("reason", "expire"):
            if d[optionals] is None:
                del d[optionals]
        return yaml.dump(
            d,
            stream=stream,
            Dumper=_ManifestDumper,
            sort_keys=False,
        )

    @classmethod
    def load(cls, str_or_stream: Union[str, TextIO]) -> "Manifest":
        d = yaml.safe_load(str_or_stream)
        if not isinstance(d, dict):
            raise ValueError("Invalid manifest: not a mapping")
        if "swhids" in d and isinstance(d["swhids"], list) and len(d["swhids"]) < 1:
            raise ValueError("Invalid manifest: list of SWHID is empty")
        return Manifest(**d)


ShareIdentifier = str
AgePublicKey = str
AgeSecretKey = str
AgeEncryptedPayload = bytes
AgeArmoredEncryptedPayload = str


class WrongDecryptionKey(Exception):
    pass


def age_encrypt(
    public_key: AgePublicKey, cleartext: bytes, armored_output=False
) -> AgeEncryptedPayload:
    # Make mypy happy
    assert RAGE_PATH is not None
    cmdline = [RAGE_PATH, "--encrypt", "--recipient", public_key]
    # Is output in text mode?
    if armored_output:
        cmdline.append("--armor")
    cmdline.extend(["--output", "-", "-"])
    age_proc = check_call(cmdline, input=cleartext)
    return age_proc.stdout


def age_encrypt_armored(
    public_key: AgePublicKey, cleartext: bytes
) -> AgeArmoredEncryptedPayload:
    return age_encrypt(public_key, cleartext, armored_output=True).decode("us-ascii")


def age_decrypt(
    secret_key: AgeSecretKey,
    ciphertext: Union[AgeEncryptedPayload, AgeArmoredEncryptedPayload],
) -> bytes:
    with tempfile.NamedTemporaryFile("w") as identity_file:
        os.chmod(identity_file.name, 0o400)
        identity_file.write(secret_key)
        identity_file.write("\n")
        identity_file.flush()
        return age_decrypt_from_identity(identity_file.name, ciphertext)


def age_decrypt_from_identity(
    identity_file: str,
    ciphertext: Union[AgeEncryptedPayload, AgeArmoredEncryptedPayload],
) -> bytes:
    if len(ciphertext) == 0:
        raise ValueError("ciphertext cannot be empty")
    # Make mypy happy
    assert RAGE_PATH is not None
    if isinstance(ciphertext, str):
        ciphertext = ciphertext.encode("us-ascii")
    cmdline = [
        RAGE_PATH,
        "--decrypt",
        "--identity",
        identity_file,
        "--output",
        "-",
        "-",
    ]
    age_proc = subprocess.run(cmdline, input=ciphertext, capture_output=True)
    if age_proc.returncode != 0 and b"No matching keys found" in age_proc.stderr:
        raise WrongDecryptionKey()
    age_proc.check_returncode()
    return age_proc.stdout


def generate_age_keypair() -> Tuple[AgePublicKey, AgeSecretKey]:
    # Make mypy happy
    assert RAGE_KEYGEN_PATH is not None
    cmdline = [RAGE_KEYGEN_PATH]
    rage_keygen_proc = check_call(cmdline, text=True)
    public_key_matches = re.search(
        r"^# public key: (age1.*)$", rage_keygen_proc.stdout, re.MULTILINE
    )
    assert public_key_matches
    public_key = public_key_matches.group(1)
    secret_key_matches = re.search(
        r"^(AGE-SECRET-KEY-.*)$", rage_keygen_proc.stdout, re.MULTILINE
    )
    assert secret_key_matches
    secret_key = secret_key_matches.group(1)
    return (public_key, secret_key)


def list_yubikey_identities() -> List[Tuple[ShareIdentifier, AgeSecretKey]]:
    age_plugin_yubikey_path = shutil.which("age-plugin-yubikey")
    if age_plugin_yubikey_path is None:
        raise FileNotFoundError("`age-plugin-yubikey` not found in path")
    cmdline = [age_plugin_yubikey_path, "--identity"]
    age_plugin_yubikey_proc = check_call(cmdline, text=True)
    # Split on empty lines
    descriptions = age_plugin_yubikey_proc.stdout.split("\n\n")
    identities = []
    for description in descriptions:
        if len(description.strip()) == 0:
            continue
        yubikey_identifier_matches = re.search(
            r"^#[ ]+Serial: ([^,]+), Slot: (\S+)", description, flags=re.MULTILINE
        )
        age_secret_key_matches = re.search(
            r"^(AGE-PLUGIN-YUBIKEY-\S+)", description, flags=re.MULTILINE
        )
        if not yubikey_identifier_matches or not age_secret_key_matches:
            raise ValueError("Unable to parse `age-yubikey-plugin --identity` output")
        yubikey_identifier = (
            f"YubiKey serial {yubikey_identifier_matches.group(1)} "
            f"slot {yubikey_identifier_matches.group(2)}"
        )
        age_secret_key = age_secret_key_matches.group(1)
        identities.append((yubikey_identifier, age_secret_key))
    return identities


@attrs.define
class _SecretSharingGroup:
    minimum_required_shares: int = attrs.field(
        validator=attrs.validators.instance_of(int)
    )
    recipient_keys: Dict[ShareIdentifier, AgePublicKey] = attrs.field(
        validator=attrs.validators.instance_of(dict)
    )

    def group_parameters(self) -> Tuple[int, int]:
        if self.minimum_required_shares == 1:
            return (1, 1)
        return (self.minimum_required_shares, len(self.recipient_keys))


@attrs.define
class SecretSharing:
    minimum_required_groups: int = attrs.field(
        validator=[attrs.validators.instance_of(int), attrs.validators.ge(2)]
    )
    groups: Dict[str, _SecretSharingGroup] = attrs.field(
        validator=attrs.validators.instance_of(dict)
    )

    @groups.validator
    def _check_groups_len(self, attribute, groups):
        if len(groups) < self.minimum_required_groups:
            raise ValueError("Not enough groups according to the minimum required")

    @groups.validator
    def _check_groups_no_duplicate_identifier(self, _attribute, groups):
        share_ids = [
            share_id for g in groups.values() for share_id in g.recipient_keys.keys()
        ]
        if len(share_ids) != len(set(share_ids)):
            raise ValueError("Duplicate share identifier")

    @groups.validator
    def _check_groups_no_duplicate_recipient(self, _attribute, groups):
        recipients = [
            recipient_key
            for g in groups.values()
            for recipient_key in g.recipient_keys.values()
        ]
        if len(recipients) != len(set(recipients)):
            raise ValueError("Duplicate recipient public key")

    @classmethod
    def from_dict(cls, d: dict) -> Self:
        if not isinstance(d, dict):
            raise ValueError("Secret sharing configuration is missing")
        if "groups" not in d:
            raise ValueError("Configuration is missing group description")
        if not isinstance(d["groups"], dict):
            raise ValueError("`groups` must be a dict")
        if "minimum_required_groups" not in d:
            raise ValueError("Configuration is missing `minimum_required_groups`")
        return cls(
            minimum_required_groups=d["minimum_required_groups"],
            groups={
                name: _SecretSharingGroup(**group_d)
                for name, group_d in d["groups"].items()
            },
        )

    @property
    def share_ids(self) -> Set[ShareIdentifier]:
        return {
            share_id
            for group in self.groups.values()
            for share_id in group.recipient_keys.keys()
        }

    def _generate_mnemonics(
        self, secret_key: AgeSecretKey
    ) -> Iterable[Tuple[_SecretSharingGroup, List[str]]]:
        hrp, data, spec = bech32_decode(secret_key)
        assert hrp == "age-secret-key-"
        secret_key_data = bytes(convert_bits(data, 5, 8))
        assert len(secret_key_data) == 32
        mnemonics = shamir_mnemonic.generate_mnemonics(
            self.minimum_required_groups,
            [g.group_parameters() for g in self.groups.values()],
            secret_key_data,
        )
        return zip(self.groups.values(), mnemonics)

    def generate_encrypted_shares(
        self, identifier: str, secret_key: AgeSecretKey
    ) -> Dict[ShareIdentifier, AgeArmoredEncryptedPayload]:
        encrypted_shares: Dict[ShareIdentifier, AgeArmoredEncryptedPayload] = {}
        for group, mnemonics in self._generate_mnemonics(secret_key):
            # When a group require only one share to be complete, we actually
            # implement this by giving to to everyone in the group the same
            # share (as required by shamir-mnemonic because of “the maths”).
            mnemonics_iter = (
                itertools.repeat(mnemonics[0])
                if group.minimum_required_shares == 1
                else iter(mnemonics)
            )
            for share_id, recipient_key, mnemonic in zip(
                group.recipient_keys.keys(),
                group.recipient_keys.values(),
                mnemonics_iter,
            ):
                # We prefix each mnemonic by the removal identifier in our encrypted
                # payload. In case a share holder remotely decrypts their payload, they can
                # verify it came from the right recovery bundle before sending back the
                # decrypted mnemonics.
                cleartext = f"[{identifier}] {mnemonic}"
                encrypted_shares[share_id] = age_encrypt_armored(
                    recipient_key, cleartext.encode("us-ascii")
                )
        return encrypted_shares


class SecretRecoveryError(Exception):
    pass


ObjectDecryptionKeyProvider = Callable[[Manifest], AgeSecretKey]
ShareDecryptionKeys = Iterator[Tuple[ShareIdentifier, AgeSecretKey]]
ShareDecryptionKeysProvider = Callable[[], ShareDecryptionKeys]


def recover_object_decryption_key_from_encrypted_shares(
    encrypted_shares: Dict[ShareIdentifier, AgeArmoredEncryptedPayload],
    share_decryption_keys_provider: ShareDecryptionKeysProvider,
    decrypted_mnemonic_processor: Optional[Callable[[str, Optional[str]], None]] = None,
    known_mnemonics: Optional[List[str]] = None,
) -> str:
    from shamir_mnemonic.recovery import RecoveryState
    from shamir_mnemonic.share import Share

    def mnemonics_from_known() -> Iterator[str]:
        if known_mnemonics:
            yield from known_mnemonics

    def mnemonics_from_provider() -> Iterator[str]:
        for share_id, secret_key in share_decryption_keys_provider():
            mnemonic = age_decrypt(secret_key, encrypted_shares[share_id]).decode(
                "us-ascii"
            )
            if decrypted_mnemonic_processor:
                decrypted_mnemonic_processor(mnemonic, share_id)
            yield mnemonic

    # TODO: We could provide better feedback on how our progress. This
    # would require a different API though.
    # shamir-mnemonic command line outputs something like:
    #   Completed 1 of 3 groups needed:
    #   ✓ 1 of 1 shares needed from group union echo acrobat
    #   ● 1 of 2 shares needed from group union echo beard
    #   ✗ 0 shares from group union echo check
    # For implementation see:
    # https://github.com/trezor/python-shamir-mnemonic/blob/c919df72/shamir_mnemonic/cli.py#L156-196
    recovery_state = RecoveryState()
    for mnemonic in itertools.chain(mnemonics_from_known(), mnemonics_from_provider()):
        # Strip bundle removal identifier if it was given
        mnemonic = re.sub(r"^\[.*\] ([a-z ]+)$", R"\1", mnemonic)
        share = Share.from_mnemonic(mnemonic)
        recovery_state.add_share(share)
        if recovery_state.is_complete():
            # no passphrase has been set when creating the mnemonics, so we need
            # to pass an empty string
            secret_key_data = recovery_state.recover(passphrase=b"")
            assert len(secret_key_data) == 32
            return bech32_encode(
                "age-secret-key-",
                list(convert_bits(secret_key_data, 8, 5, True)),
                Bech32Encoding.BECH32,
            ).upper()
    raise SecretRecoveryError("Unable to decrypt enough secrets")


MANIFEST_ARCNAME = "manifest.yml"


class RecoveryBundle:
    def __init__(
        self,
        path: str,
        object_decryption_key_provider: Optional[ObjectDecryptionKeyProvider] = None,
    ):
        self._zip = ZipFile(path, "r")
        self._manifest = Manifest.load(self._zip.read(MANIFEST_ARCNAME).decode("utf-8"))
        self._cached_object_decryption_key: Optional[str] = None
        if object_decryption_key_provider:
            self._object_decryption_key_provider = object_decryption_key_provider
        else:

            def failing_provider(_):
                raise ValueError(
                    "No `object_decryption_key_provider` has been given for this bundle."
                )

            self._object_decryption_key_provider = failing_provider

    @property
    def version(self) -> int:
        return self._manifest.version

    @property
    def removal_identifier(self) -> str:
        return self._manifest.removal_identifier

    @property
    def created(self) -> datetime:
        return self._manifest.created

    @property
    def swhids(self) -> List[str]:
        return self._manifest.swhids

    @property
    def reason(self) -> Optional[str]:
        return self._manifest.reason

    @property
    def expire(self) -> Optional[datetime]:
        return self._manifest.expire

    @property
    def share_ids(self) -> Set[ShareIdentifier]:
        return set(self._manifest.decryption_key_shares.keys())

    @property
    def object_decryption_key(self) -> AgeSecretKey:
        if self._cached_object_decryption_key is None:
            self._cached_object_decryption_key = self._object_decryption_key_provider(
                self._manifest
            )
        return self._cached_object_decryption_key

    def encrypted_secret(self, share_id: ShareIdentifier) -> AgeArmoredEncryptedPayload:
        return self._manifest.decryption_key_shares[share_id]

    def dump_manifest(self) -> str:
        result = self._manifest.dump()
        # make mypy happy
        assert result is not None
        return result

    def _extract(self, arcname: str) -> bytes:
        with self._zip.open(arcname) as f:
            return age_decrypt(self.object_decryption_key, f.read())

    def get_dict(self, swhid: ExtendedSWHID) -> Dict[str, Any]:
        arcname = _swhid_to_arcname(swhid)
        return kafka_to_value(self._extract(arcname))

    def write_content_data(self, swhid: ExtendedSWHID, dest: BinaryIO):
        content: Content = Content.from_dict(self.get_dict(swhid))
        if content.data is None:
            raise ValueError("Unserialized Content has no data")
        dest.write(content.data)

    def _objects(
        self,
        dir: str,
        cls: Type[BaseModel],
        name_filter: Optional[Callable[[str], bool]] = None,
    ):
        if name_filter is None:
            name_filter = lambda name: True  # noqa: E731
        for zip_info in sorted(
            self._zip.infolist(), key=operator.attrgetter("filename")
        ):
            if not zip_info.filename.startswith(f"{dir}/"):
                continue
            if zip_info.is_dir():
                continue
            if not name_filter(zip_info.filename.split("/")[-1]):
                continue
            d = kafka_to_value(
                age_decrypt(self.object_decryption_key, self._zip.read(zip_info))
            )
            yield cls.from_dict(d)

    def contents(self) -> Iterator[Content]:
        yield from self._objects("contents", Content)

    def skipped_contents(self) -> Iterator[SkippedContent]:
        yield from self._objects("skipped_contents", SkippedContent)

    def directories(self) -> Iterator[Directory]:
        yield from self._objects("directories", Directory)

    def revisions(self) -> Iterator[Revision]:
        yield from self._objects("revisions", Revision)

    def releases(self) -> Iterator[Release]:
        yield from self._objects("releases", Release)

    def snapshots(self) -> Iterator[Snapshot]:
        yield from self._objects("snapshots", Snapshot)

    def origins(self) -> Iterator[Origin]:
        yield from self._objects("origins", Origin)

    def origin_visits(self, origin: Origin) -> Iterator[OriginVisit]:
        basename = str(origin.swhid()).replace(":", "_")
        yield from self._objects(
            "origin_visits", OriginVisit, lambda name: name.startswith(basename)
        )

    def origin_visit_statuses(self, origin: Origin) -> Iterator[OriginVisitStatus]:
        basename = str(origin.swhid()).replace(":", "_")
        yield from self._objects(
            "origin_visit_statuses",
            OriginVisitStatus,
            lambda name: name.startswith(basename),
        )

    def raw_extrinsic_metadata(self) -> Iterator[RawExtrinsicMetadata]:
        if self.version < 2:
            return
        yield from self._objects("raw_extrinsic_metadata", RawExtrinsicMetadata)

    def extids(self) -> Iterator[ExtID]:
        if self.version < 2:
            return
        yield from self._objects("extids", ExtID)

    def restore(
        self, storage: StorageInterface, progressbar: ProgressBarInit = no_progressbar
    ) -> Dict[str, int]:
        def _origin_add(origins: List[Origin]) -> Dict[str, int]:
            origin_result: collections.Counter[str] = collections.Counter()
            origin_result += storage.origin_add(origins)
            for origin in origins:
                # Interestingly enough, origin_visit_add() and origin_visit_status_add()
                # do not return result info.
                # Also you _do_ need to pass a list and not an iterator otherwise
                # nothing gets added.
                origin_visits = list(self.origin_visits(origin))
                storage.origin_visit_add(origin_visits)
                origin_result["origin_visit:add"] += len(origin_visits)
                origin_visit_statuses = list(self.origin_visit_statuses(origin))
                storage.origin_visit_status_add(origin_visit_statuses)
                origin_result["origin_visit_status:add"] += len(origin_visit_statuses)
            return dict(origin_result)

        steps: List[
            Tuple[Callable[[List[Any]], Dict[str, int]], Callable[[], Iterator[Any]]]
        ] = [
            (storage.content_add, self.contents),
            (storage.skipped_content_add, self.skipped_contents),
            (storage.directory_add, self.directories),
            (storage.revision_add, self.revisions),
            (storage.release_add, self.releases),
            (storage.snapshot_add, self.snapshots),
            (_origin_add, self.origins),
        ]
        if self.version >= 2:
            steps.extend(
                [
                    (storage.raw_extrinsic_metadata_add, self.raw_extrinsic_metadata),
                    (storage.extid_add, self.extids),
                ]
            )

        result: collections.Counter[str] = collections.Counter()
        bar: ProgressBar[int]
        with progressbar(
            length=len(self.swhids), label="Restoring recovery bundle…"
        ) as bar:
            for add, source in steps:
                for chunk_it in grouper(source(), RECOVERY_BUNDLE_RESTORE_CHUNK_SIZE):
                    chunk = list(chunk_it)
                    result += add(chunk)
                    bar.update(n_steps=len(chunk))

        log_lines = [
            "Restoration complete. Results: ",
            "- Content objects added: %(content:add)s",
            "- Total bytes added to objstorage: %(content:add:bytes)s",
            "- SkippedContent objects added: %(skipped_content:add)s",
            "- Directory objects added: %(directory:add)s",
            "- Revision objects added: %(revision:add)s",
            "- Release objects added: %(release:add)s",
            "- Snapshot objects added: %(snapshot:add)s",
            "- Origin objects added: %(origin:add)s",
            "- OriginVisit objects added: %(origin_visit:add)s",
            "- OriginVisitStatus objects added: %(origin_visit_status:add)s",
        ]
        if "ori_metadata:add" in result:
            log_lines.append(
                "- RawExtrinsicMetadata objects for origins added: %(ori_metadata:add)s"
            )
        if "snp_metadata:add" in result:
            log_lines.append(
                "- RawExtrinsicMetadata objects for snapshots added: %(snp_metadata:add)s"
            )
        if "rev_metadata:add" in result:
            log_lines.append(
                "- RawExtrinsicMetadata objects for revisions added: %(rev_metadata:add)s"
            )
        if "rel_metadata:add" in result:
            log_lines.append(
                "- RawExtrinsicMetadata objects for releases added: %(rel_metadata:add)s"
            )
        if "dir_metadata:add" in result:
            log_lines.append(
                "- RawExtrinsicMetadata objects for directories added: %(dir_metadata:add)s"
            )
        if "cnt_metadata:add" in result:
            log_lines.append(
                "- RawExtrinsicMetadata objects for contents added: %(cnt_metadata:add)s"
            )
        if "extid:add" in result:
            log_lines.append("- ExtID objects added: %(extid:add)s")
        logger.info("\n".join(log_lines), result)
        return dict(result)

    def rollover(self, secret_sharing: SecretSharing):
        """Update the recovery bundle encrypted shared secrets using the given
        configuration.

        It is useful when a secret holder needs to be added or removed, or to
        switch to an entirely new scheme.

        This method splits the decryption key into new encrypted shares. The
        decryption key stays the same. The mnemonics will be new.

        A new recovery bundle file is created with an updated manifest which
        then atomically replaces the existing file.
        """
        new_decryption_key_shares = secret_sharing.generate_encrypted_shares(
            self.removal_identifier, self.object_decryption_key
        )
        # Turns out there is no way currently to update or delete a member of a Zip archive
        # in Python zipfile module. See https://github.com/python/cpython/issues/51067
        # So we are going to manually copy all members from the original zip to the other.
        # This means fully unpacking each file in memory.
        #
        # We are going to create the new zip in the same directory as the original
        # so we can do an atomic replacement using rename(2).
        assert self._zip.filename is not None
        bundle_path = Path(self._zip.filename)
        bundle_dir = bundle_path.parent
        with tempfile.NamedTemporaryFile(
            mode="w+b",
            dir=bundle_dir,
            delete=False,
            prefix=f".{bundle_path.stem}_",
            suffix=".swh-recovery-bundle",
        ) as f:
            try:
                self._manifest.decryption_key_shares = new_decryption_key_shares
                with ZipFile(f, "a") as new_zip:
                    for zipinfo in self._zip.infolist():
                        # We skip the old manifest…
                        if zipinfo.filename == MANIFEST_ARCNAME:
                            continue
                        new_zip.writestr(zipinfo, self._zip.read(zipinfo))
                    # …and add the new one at the end.
                    new_zip.writestr(
                        MANIFEST_ARCNAME, typing.cast(str, self._manifest.dump())
                    )
                f.close()
                os.rename(f.name, bundle_path)
                # Reopen the current zip file
                self._zip = ZipFile(bundle_path, "r")
            finally:
                # Always unlink the temporary file path. Either it already has
                # been renamed to the old file, or something went wrong.
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(f.name)


def _swhid_to_arcname(swhid: ExtendedSWHID):
    basename = str(swhid).replace(":", "_")
    if swhid.object_type == ExtendedObjectType.CONTENT:
        return f"contents/{basename}.age"
    if swhid.object_type == ExtendedObjectType.DIRECTORY:
        return f"directories/{basename}.age"
    if swhid.object_type == ExtendedObjectType.REVISION:
        return f"revisions/{basename}.age"
    if swhid.object_type == ExtendedObjectType.RELEASE:
        return f"releases/{basename}.age"
    if swhid.object_type == ExtendedObjectType.SNAPSHOT:
        return f"snapshots/{basename}.age"
    if swhid.object_type == ExtendedObjectType.ORIGIN:
        return f"origins/{basename}.age"
    raise NotImplementedError(f"Unknown object type {swhid.object_type}")


def _from_hashes(
    sha1: Optional[bytes] = None,
    sha1_git: Optional[bytes] = None,
    sha256: Optional[bytes] = None,
    blake2s256: Optional[bytes] = None,
) -> HashDict:
    d = HashDict()
    if sha1 is not None:
        d["sha1"] = sha1
    if sha1_git is not None:
        d["sha1_git"] = sha1_git
    if sha256 is not None:
        d["sha256"] = sha256
    if blake2s256 is not None:
        d["blake2s256"] = blake2s256
    return d


class RecoveryBundleCreator:
    def __init__(
        self,
        path: str,
        storage: StorageInterface,
        removal_identifier: str,
        object_public_key: AgePublicKey,
        decryption_key_shares: Dict[str, str],
        registration_callback: Optional[Callable[[BaseModel], None]] = None,
    ):
        self._path = path
        self._storage = storage
        self._removal_identifier = removal_identifier
        self._created = datetime.now(timezone.utc)
        self._pk = object_public_key
        self._decryption_key_shares = decryption_key_shares
        if registration_callback:
            self._registration_callback = registration_callback
        else:
            self._registration_callback = lambda _: None

    def __enter__(self) -> Self:
        self._zip = ZipFile(self._path, "x")
        self._manifest = Manifest(
            version=2,
            removal_identifier=self._removal_identifier,
            created=self._created,
            swhids=[],
            decryption_key_shares=self._decryption_key_shares,
        )
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            if exc_type is not None:
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(self._path)
                return False
            if len(self._manifest.swhids) == 0:
                raise ValueError("Refusing to create an empty recovery bundle")
            if len(self._manifest.decryption_key_shares) == 0:
                raise ValueError("`decryption_key_shares` has not been set")
            self._zip.writestr(MANIFEST_ARCNAME, self._manifest.dump())
        except:  # noqa: E722
            with contextlib.suppress(FileNotFoundError):
                os.unlink(self._path)
            raise
        finally:
            self._zip.close()

    def set_reason(self, reason: str):
        self._manifest.reason = reason

    def set_expire(self, expire: datetime):
        if expire < self._manifest.created:
            raise ValueError("expiration date is in the past")
        self._manifest.expire = expire

    def _write(self, arcname: str, data: bytes):
        self._zip.writestr(arcname, age_encrypt(self._pk, data))

    def _add_skipped_content(
        self, swhid: ExtendedSWHID, index: int, skipped_content: SkippedContent
    ):
        basename = str(swhid).replace(":", "_")
        arcname = f"skipped_contents/{basename}_{index}.age"
        self._write(arcname, value_to_kafka(skipped_content.to_dict()))

    def _add_contents(
        self, content_swhids: List[ExtendedSWHID]
    ) -> Iterable[Content | SkippedContent | ExtID]:
        assert all(
            swhid.object_type == ExtendedObjectType.CONTENT for swhid in content_swhids
        )
        for swhid, content in zip(
            content_swhids,
            self._storage.content_get(
                [swhid.object_id for swhid in content_swhids], algo="sha1_git"
            ),
        ):
            if content is None:
                # content_get() gave us nothing… maybe the SWHID matches some SkippedContent?
                skipped_contents = self._storage.skipped_content_find(
                    {"sha1_git": swhid.object_id}
                )
                if len(skipped_contents) == 0:
                    raise ValueError(f"Unable to find {swhid} in storage")
                for index, skipped_content in enumerate(skipped_contents, start=1):
                    self._add_skipped_content(swhid, index, skipped_content)
                    yield skipped_content
            else:
                data = self._storage.content_get_data(_from_hashes(**content.hashes()))
                if data is None:
                    raise ValueError(f"Unable to retrieve data for {swhid}")
                populated_content = content.from_data(
                    data,
                    status=content.status,
                    ctime=content.ctime,
                )
                self._write(
                    _swhid_to_arcname(swhid),
                    value_to_kafka(populated_content.to_dict()),
                )
                yield populated_content
        yield from self._add_extids(
            CoreSWHIDObjectType.CONTENT, [swhid.object_id for swhid in content_swhids]
        )

    def _add_directories(
        self, directory_swhids: List[ExtendedSWHID]
    ) -> Iterable[Directory | ExtID]:
        assert all(
            swhid.object_type == ExtendedObjectType.DIRECTORY
            for swhid in directory_swhids
        )
        directory_ids = [swhid.object_id for swhid in directory_swhids]
        it = zip(
            directory_swhids,
            swh.storage.algos.directory.directory_get_many_with_possibly_duplicated_entries(  # noqa: B950
                self._storage, directory_ids
            ),
        )
        for swhid, result in it:
            if result is None:
                raise ValueError(f"Unable to find {swhid} in storage")
            _corrupted, directory = result
            # If it's corrupted we still should backup it anyway
            self._write(_swhid_to_arcname(swhid), value_to_kafka(directory.to_dict()))
            yield directory
        yield from self._add_extids(
            CoreSWHIDObjectType.DIRECTORY,
            [swhid.object_id for swhid in directory_swhids],
        )

    def _add_revisions(
        self, revision_swhids: List[ExtendedSWHID]
    ) -> Iterator[Revision | ExtID]:
        assert all(
            swhid.object_type == ExtendedObjectType.REVISION
            for swhid in revision_swhids
        )
        for swhid, revision in zip(
            revision_swhids,
            self._storage.revision_get(
                [swhid.object_id for swhid in revision_swhids], ignore_displayname=True
            ),
        ):
            if revision is None:
                raise ValueError(f"Unable to find {swhid} in storage")
            self._write(_swhid_to_arcname(swhid), value_to_kafka(revision.to_dict()))
            yield revision
        yield from self._add_extids(
            CoreSWHIDObjectType.REVISION, [swhid.object_id for swhid in revision_swhids]
        )

    def _add_releases(
        self, release_swhids: List[ExtendedSWHID]
    ) -> Iterator[Release | ExtID]:
        assert all(
            swhid.object_type == ExtendedObjectType.RELEASE for swhid in release_swhids
        )
        for swhid, release in zip(
            release_swhids,
            self._storage.release_get(
                [swhid.object_id for swhid in release_swhids], ignore_displayname=True
            ),
        ):
            if release is None:
                raise ValueError(f"Unable to find {swhid} in storage")
            self._write(_swhid_to_arcname(swhid), value_to_kafka(release.to_dict()))
            yield release
        yield from self._add_extids(
            CoreSWHIDObjectType.RELEASE, [swhid.object_id for swhid in release_swhids]
        )

    def _add_snapshots(
        self, snapshot_swhids: List[ExtendedSWHID]
    ) -> Iterator[Snapshot | ExtID]:
        assert all(
            swhid.object_type == ExtendedObjectType.SNAPSHOT
            for swhid in snapshot_swhids
        )
        for swhid in snapshot_swhids:
            snapshot = swh.storage.algos.snapshot.snapshot_get_all_branches(
                self._storage, swhid.object_id
            )
            if snapshot is None:
                raise ValueError(f"Unable to find {swhid} in storage")
            self._write(_swhid_to_arcname(swhid), value_to_kafka(snapshot.to_dict()))
            yield snapshot
        yield from self._add_extids(
            CoreSWHIDObjectType.SNAPSHOT, [swhid.object_id for swhid in snapshot_swhids]
        )

    def _add_origin_visit(self, basename: str, visit: OriginVisit):
        arcname = f"origin_visits/{basename}_" f"{visit.visit}.age"
        self._write(arcname, value_to_kafka(visit.to_dict()))

    def _add_origin_visit_status(self, basename: str, status: OriginVisitStatus):
        arcname = (
            f"origin_visit_statuses/{basename}_"
            f"{status.visit}_"
            f"{status.date.isoformat(timespec='microseconds').replace(':', '_')}.age"
        )
        self._write(arcname, value_to_kafka(status.to_dict()))

    def _add_origins(
        self, origin_swhids: List[ExtendedSWHID]
    ) -> Iterator[Origin | OriginVisit | OriginVisitStatus]:
        assert all(
            swhid.object_type == ExtendedObjectType.ORIGIN for swhid in origin_swhids
        )
        for swhid, origin_d in zip(
            origin_swhids,
            self._storage.origin_get_by_sha1(
                [swhid.object_id for swhid in origin_swhids]
            ),
        ):
            if origin_d is None:
                raise ValueError(f"Unable to find {swhid} in storage")
            origin = Origin.from_dict(origin_d)
            basename = str(swhid).replace(":", "_")
            arcname = f"origins/{basename}.age"
            self._write(arcname, value_to_kafka(origin_d))
            yield origin
            for origin_visit_with_statuses in stream_results(
                self._storage.origin_visit_get_with_statuses, origin.url
            ):
                self._add_origin_visit(basename, origin_visit_with_statuses.visit)
                yield origin_visit_with_statuses.visit
                for origin_visit_status in origin_visit_with_statuses.statuses:
                    self._add_origin_visit_status(basename, origin_visit_status)
                    yield origin_visit_status

    def _add_raw_extrinsic_metadata(
        self, emd_swhids: List[ExtendedSWHID]
    ) -> Iterator[RawExtrinsicMetadata]:
        assert all(
            swhid.object_type == ExtendedObjectType.RAW_EXTRINSIC_METADATA
            for swhid in emd_swhids
        )
        emds = self._storage.raw_extrinsic_metadata_get_by_ids(
            [swhid.object_id for swhid in emd_swhids]
        )
        missing_emd_swhids = set(emd_swhids) - {emd.swhid() for emd in emds}
        if missing_emd_swhids:
            raise ValueError(
                f"Unable to retrieve {', '.join(str(swhid) for swhid in missing_emd_swhids)}"
            )
        # Here we do some tricks to 0-pad the index to the right size
        # If we have 1234 RawExtrinsicMetadata objects, `len(str(len(emds)))``
        # will be 4. We thus get `emd_index_format` to be`{:04d}`.
        # Calling `emd_index_format.format(33)` results in `0033`.
        emd_index_format = "{" f":0{len(str(len(emds)))}d" "}"
        for emd_index, emd in enumerate(emds, start=1):
            basename = str(emd.swhid()).replace(":", "_")
            arcname = (
                "raw_extrinsic_metadata/"
                f"{emd_index_format.format(emd_index)}_{basename}.age"
            )
            self._write(arcname, value_to_kafka(emd.to_dict()))
            yield emd

    def _add_extids(
        self, target_type: CoreSWHIDObjectType, target_ids: List[bytes]
    ) -> Iterator[ExtID]:
        for extid in self._storage.extid_get_from_target(target_type, target_ids):
            assert extid.id, "id for ExtID should have been computed!"
            arcname = f"extids/{extid.id.hex()}.age"
            self._write(arcname, value_to_kafka(extid.to_dict()))
            yield extid

    def backup_swhids(self, swhids: Iterable[ExtendedSWHID]) -> int:
        handlers: Dict[
            ExtendedObjectType,
            Callable[[List[ExtendedSWHID]], Iterable[BaseModel]],
        ] = {
            ExtendedObjectType.CONTENT: self._add_contents,
            ExtendedObjectType.DIRECTORY: self._add_directories,
            ExtendedObjectType.REVISION: self._add_revisions,
            ExtendedObjectType.RELEASE: self._add_releases,
            ExtendedObjectType.SNAPSHOT: self._add_snapshots,
            ExtendedObjectType.ORIGIN: self._add_origins,
            ExtendedObjectType.RAW_EXTRINSIC_METADATA: self._add_raw_extrinsic_metadata,
        }
        count = 0
        for obj in iter_swhids_grouped_by_type(
            swhids, handlers=handlers, collector=list
        ):
            self._registration_callback(obj)
            if hasattr(obj, "swhid"):
                self._manifest.swhids.append(str(obj.swhid()))
            count += 1
        return count
