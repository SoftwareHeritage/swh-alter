# Copyright (C) 2023-2024 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import collections
from datetime import datetime, timedelta
from functools import partial, reduce
import itertools
import logging
import operator
import re
import statistics
import time
from typing import (
    Any,
    Dict,
    FrozenSet,
    Iterator,
    List,
    NamedTuple,
    Optional,
    Set,
    TextIO,
    Tuple,
    cast,
)

import humanize
from tabulate import tabulate
import yaml

from swh.core.utils import grouper
from swh.graph.http_client import RemoteGraphClient
from swh.journal.writer.kafka import KafkaJournalWriter
from swh.model.model import BaseModel, Content, KeyType, Origin
from swh.model.swhids import CoreSWHID, ExtendedObjectType, ExtendedSWHID
from swh.model.swhids import ObjectType as CoreSWHIDObjectType
from swh.objstorage.exc import Error as ObjstorageError
from swh.objstorage.exc import ObjNotFoundError
from swh.objstorage.interface import (
    CompositeObjId,
    ObjStorageInterface,
    objid_from_dict,
)
from swh.search.interface import SearchInterface
from swh.storage.interface import ObjectDeletionInterface, StorageInterface
from swh.storage.proxies.masking.db import MaskedState, MaskingAdmin, MaskingRequest

from .inventory import RootsNotFound, get_raw_extrinsic_metadata, make_inventory
from .mirror_notification_watcher import MASKING_REQUEST_IDENTIFIER_PREFIX
from .progressbar import ProgressBar, ProgressBarInit, no_progressbar
from .recovery_bundle import (
    AgeSecretKey,
    RecoveryBundle,
    RecoveryBundleCreator,
    SecretSharing,
    generate_age_keypair,
)
from .removable import mark_removable
from .utils import get_filtered_objects

logger = logging.getLogger(__name__)


OBJSTORAGE_DELETE_MAX_ATTEMPTS = 3


class RemoverError(Exception):
    pass


class MaskingRequestNotFound(Exception):
    def __init__(self, masking_request_slug: str):
        self.masking_request_slug = masking_request_slug

    def __str__(self) -> str:
        return f"Masking request “{self.masking_request_slug}” not found."


def _secho(msg, **kwargs):
    """Log at info level, passing kwargs as styles for click.secho()"""
    logger.info(msg, extra={"style": kwargs})


def format_duration(seconds: float) -> str:
    return humanize.precisedelta(
        timedelta(seconds=seconds), minimum_unit="milliseconds"
    )


class Removable(NamedTuple):
    """Aggregates information returned by :py:meth:`Remover.get_removable` to
    be then used with :py:meth:`Remover.create_recovery_bundle`."""

    removable_swhids: List[ExtendedSWHID]
    referencing: List[ExtendedSWHID]

    def print_plan(self) -> None:
        ordering = {
            t: i
            for i, t in enumerate(
                (
                    ExtendedObjectType.ORIGIN,
                    ExtendedObjectType.SNAPSHOT,
                    ExtendedObjectType.RELEASE,
                    ExtendedObjectType.REVISION,
                    ExtendedObjectType.DIRECTORY,
                    ExtendedObjectType.CONTENT,
                    ExtendedObjectType.RAW_EXTRINSIC_METADATA,
                )
            )
        }
        sorted_swhids = sorted(
            self.removable_swhids, key=lambda swhid: ordering[swhid.object_type]
        )
        _secho("Removal plan:")
        for object_type, grouped_swhids in itertools.groupby(
            sorted_swhids, key=operator.attrgetter("object_type")
        ):
            _secho(f"- {object_type.name.capitalize()}: {len(list(grouped_swhids))}")
        _secho(
            "- … and more objects that are not addresseable by a SWHID "
            "(OriginVisit, OriginVisitStatus, ExtID)."
        )


STORAGE_OBJECT_DELETE_CHUNK_SIZE = 200


class Remover:
    """Helper class used to perform a removal."""

    def __init__(
        self,
        /,
        storage: StorageInterface,
        graph_client: Optional[RemoteGraphClient] = None,
        known_missing: Optional[Set[ExtendedSWHID]] = None,
        restoration_storage: Optional[StorageInterface] = None,
        removal_searches: Optional[Dict[str, SearchInterface]] = None,
        removal_storages: Optional[Dict[str, ObjectDeletionInterface]] = None,
        removal_objstorages: Optional[Dict[str, ObjStorageInterface]] = None,
        removal_journals: Optional[Dict[str, KafkaJournalWriter]] = None,
        masking_admin: Optional[MaskingAdmin] = None,
        progressbar: Optional[ProgressBarInit] = None,
    ):
        self.storage = storage
        self.graph_client = graph_client
        self.known_missing = known_missing or set()
        self.restoration_storage = restoration_storage
        self.removal_searches = removal_searches if removal_searches else {}
        self.removal_storages = removal_storages if removal_storages else {}
        self.removal_objstorages = removal_objstorages if removal_objstorages else {}
        self.removal_journals = removal_journals if removal_journals else {}
        self.masking_admin = masking_admin
        self.recovery_bundle_path: Optional[str] = None
        self.object_secret_key: Optional[AgeSecretKey] = None
        self.swhids_to_remove: List[ExtendedSWHID] = []
        self.objids_to_remove: List[CompositeObjId] = []
        self.origin_urls_to_remove: List[str] = []
        self.journal_objects_to_remove: Dict[str, List[KeyType]] = (
            collections.defaultdict(list)
        )
        self.progressbar: ProgressBarInit = (
            progressbar if progressbar is not None else no_progressbar
        )

    def get_removable(
        self,
        swhids: List[ExtendedSWHID],
        *,
        output_inventory_subgraph: Optional[TextIO] = None,
        output_removable_subgraph: Optional[TextIO] = None,
        output_pruned_removable_subgraph: Optional[TextIO] = None,
    ) -> Removable:
        _secho("Removing the following origins:")
        for swhid in swhids:
            _secho(f" - {swhid}")
        _secho("Finding removable objects…", fg="cyan")
        assert self.graph_client is not None
        inventory_subgraph = make_inventory(
            self.storage,
            self.graph_client,
            swhids,
            known_missing=self.known_missing,
            progressbar=self.progressbar,
        )
        if output_inventory_subgraph:
            inventory_subgraph.write_dot(output_inventory_subgraph)
            output_inventory_subgraph.close()
        removable_subgraph = mark_removable(
            self.storage,
            self.graph_client,
            inventory_subgraph,
            self.known_missing,
            self.progressbar,
        )
        if output_removable_subgraph:
            removable_subgraph.write_dot(output_removable_subgraph)
            output_removable_subgraph.close()
        referencing = list(removable_subgraph.referenced_swhids())
        removable_swhids = list(removable_subgraph.removable_swhids())
        removable_swhids.extend(
            get_raw_extrinsic_metadata(
                self.storage, removable_swhids, progressbar=self.progressbar
            )
        )
        if output_pruned_removable_subgraph:
            removable_subgraph.delete_unremovable()
            removable_subgraph.write_dot(output_pruned_removable_subgraph)
            output_pruned_removable_subgraph.close()
        return Removable(
            removable_swhids=removable_swhids,
            referencing=referencing,
        )

    def register_object(self, obj: BaseModel) -> None:
        # Register for removal from storage
        if hasattr(obj, "swhid"):
            # StorageInterface.ObjectDeletionInterface.remove uses SWHIDs
            # for reference. We hope it will handle objects without SWHIDs
            # (origin_visit, origin_visit_status) directly.
            obj_swhid = obj.swhid()
            if obj_swhid is not None:
                swhid = (
                    obj_swhid.to_extended()
                    if isinstance(obj_swhid, CoreSWHID)
                    else obj_swhid
                )
                self.swhids_to_remove.append(swhid)
                if swhid.object_type == ExtendedObjectType.CONTENT:
                    content = cast(Content, obj)
                    self.objids_to_remove.append(objid_from_dict(content.to_dict()))
        # Register for removal from the journal
        self.journal_objects_to_remove[str(obj.object_type)].append(obj.unique_key())
        # Register for removal from search
        if isinstance(obj, Origin):
            self.origin_urls_to_remove.append(obj.url)

    def register_objects_from_bundle(
        self, recovery_bundle_path: str, object_secret_key: AgeSecretKey
    ) -> RecoveryBundle:
        assert self.recovery_bundle_path is None
        assert self.object_secret_key is None

        def key_provider(_):
            return object_secret_key

        bundle = RecoveryBundle(recovery_bundle_path, key_provider)
        _secho(
            f"Resuming removal from bundle “{bundle.removal_identifier}”…",
            fg="cyan",
            bold=True,
        )
        self.recovery_bundle_path = recovery_bundle_path
        self.object_secret_key = object_secret_key

        iterchain = [
            bundle.contents(),
            bundle.skipped_contents(),
            bundle.directories(),
            bundle.revisions(),
            bundle.releases(),
            bundle.snapshots(),
        ]
        if bundle.version >= 2:
            iterchain.extend(
                [
                    bundle.raw_extrinsic_metadata(),
                    bundle.extids(),
                ]
            )
        bar: ProgressBar[int]
        with self.progressbar(
            length=len(bundle.swhids), label="Loading objects…"
        ) as bar:
            for obj in itertools.chain(*iterchain):
                self.register_object(obj)
                bar.update(n_steps=1)
            for origin in bundle.origins():
                self.register_object(origin)
                for obj in itertools.chain(
                    bundle.origin_visits(origin), bundle.origin_visit_statuses(origin)
                ):
                    self.register_object(obj)
                bar.update(n_steps=1)
        return bundle

    def create_recovery_bundle(
        self,
        /,
        secret_sharing: SecretSharing,
        requested: List[Origin | ExtendedSWHID],
        removable: Removable,
        recovery_bundle_path: str,
        removal_identifier: str,
        reason: Optional[str] = None,
        expire: Optional[datetime] = None,
        allow_empty_content_objects: bool = False,
    ) -> AgeSecretKey:
        object_public_key, self.object_secret_key = generate_age_keypair()
        decryption_key_shares = secret_sharing.generate_encrypted_shares(
            removal_identifier, self.object_secret_key
        )
        _secho("Creating recovery bundle…", fg="cyan")
        with RecoveryBundleCreator(
            path=recovery_bundle_path,
            storage=self.storage,
            removal_identifier=removal_identifier,
            requested=requested,
            referencing=removable.referencing,
            object_public_key=object_public_key,
            decryption_key_shares=decryption_key_shares,
            registration_callback=self.register_object,
            allow_empty_content_objects=allow_empty_content_objects,
        ) as creator:
            if reason is not None:
                creator.set_reason(reason)
            if expire is not None:
                try:
                    creator.set_expire(expire)
                except ValueError as ex:
                    raise RemoverError(f"Unable to set expiration date: {str(ex)}")
            creator.backup_swhids(
                removable.removable_swhids, progressbar=self.progressbar
            )
        self.recovery_bundle_path = recovery_bundle_path
        _secho("Recovery bundle created.", fg="green")
        return self.object_secret_key

    def restore_recovery_bundle(self) -> None:
        assert self.restoration_storage
        assert self.recovery_bundle_path

        def key_provider(_):
            assert self.object_secret_key
            return self.object_secret_key

        bundle = RecoveryBundle(self.recovery_bundle_path, key_provider)
        result = bundle.restore(self.restoration_storage, self.progressbar)
        # We care about the number of objects, not the byte count
        result.pop("content:add:bytes", None)
        # We don’t care about new object_references either
        result.pop("object_reference:add", None)
        total = sum(result.values())
        _secho(f"{total} objects restored.", fg="green")
        count_from_journal_objects = sum(
            len(objects) for objects in self.journal_objects_to_remove.values()
        )
        if count_from_journal_objects != total:
            _secho(
                f"{count_from_journal_objects} objects should have "
                "been restored. Something might be wrong!",
                fg="red",
                bold=True,
            )

    def remove(self, progressbar=None) -> None:
        for name, removal_search in self.removal_searches.items():
            self.remove_from_search(name, removal_search)
        for name, removal_storage in self.removal_storages.items():
            self.remove_from_storage(name, removal_storage)
        for name, journal_writer in self.removal_journals.items():
            self.remove_from_journal(name, journal_writer)
        if len(self.removal_objstorages) > 0:
            self.remove_from_objstorages()
        if self.have_new_references(self.swhids_to_remove):
            raise RemoverError(
                "New references have been added to removed objects. "
                "This invalidates the initial set of candidates for removal."
            )

    def remove_from_storage(
        self, name: str, removal_storage: ObjectDeletionInterface
    ) -> None:
        results: collections.Counter[str] = collections.Counter()
        bar: ProgressBar[int]
        with self.progressbar(
            length=len(self.swhids_to_remove),
            label=f"Removing objects from storage “{name}”…",
        ) as bar:
            for chunk_it in grouper(
                self.swhids_to_remove, STORAGE_OBJECT_DELETE_CHUNK_SIZE
            ):
                chunk_swhids = list(chunk_it)
                # Remove objects addressable by a SWHID
                results += removal_storage.object_delete(chunk_swhids)
                # Remove ExtIDs (addressable by their targets)
                chunk_core_swhids = [
                    CoreSWHID(
                        object_type=CoreSWHIDObjectType[
                            extended_swhid.object_type.name
                        ],
                        object_id=extended_swhid.object_id,
                    )
                    for extended_swhid in chunk_swhids
                    if hasattr(CoreSWHIDObjectType, extended_swhid.object_type.name)
                ]
                results += removal_storage.extid_delete_for_target(chunk_core_swhids)
                bar.update(n_steps=len(chunk_swhids))
        _secho(
            f"{results.total()} objects removed from storage “{name}”.",
            fg="green",
        )

    def remove_from_journal(
        self, name: str, journal_writer: KafkaJournalWriter
    ) -> None:
        bar: ProgressBar[Tuple[str, List[KeyType]]]
        with self.progressbar(
            self.journal_objects_to_remove.items(),
            label=f"Removing objects from journal “{name}”…",
        ) as bar:
            for object_type, keys in bar:
                journal_writer.delete(object_type, keys)
        journal_writer.flush()
        _secho(f"Objects removed from journal “{name}”.", fg="green")

    def remove_from_search(self, name: str, search: SearchInterface) -> None:
        count = 0
        with self.progressbar(
            self.origin_urls_to_remove, label=f"Removing origins from search “{name}”…"
        ) as bar:
            for origin_url in bar:
                deleted = search.origin_delete(origin_url)
                count += 1 if deleted else 0
            search.flush()
        _secho(f"{count} origins removed from search “{name}”.", fg="green")

    def remove_from_objstorages(self):
        results = []
        for name, removal_objstorage in self.removal_objstorages.items():
            results.append(self.remove_from_objstorage(name, removal_objstorage))
        not_found = reduce(set.intersection, results)
        if not_found:
            table = tabulate(
                (
                    dict(sorted(frozen_objid, key=operator.itemgetter(0)))
                    for frozen_objid in not_found
                ),
                headers="keys",
                tablefmt="github",
                disable_numparse=True,
            )
            _secho(f"Objects not found in any objstorage:\n{table}", fg="red")

    def remove_from_objstorage(
        self,
        name: str,
        objstorage: ObjStorageInterface,
    ) -> Set[FrozenSet[Tuple[str, str]]]:
        count = 0
        not_found: Set[FrozenSet[Tuple[str, str]]] = set()
        durations = []
        with self.progressbar(
            self.objids_to_remove, label=f"Removing objects from objstorage “{name}”…"
        ) as bar:
            for objid in bar:
                attempt = 1
                while True:
                    try:
                        start = time.monotonic()
                        objstorage.delete(objid)
                        durations.append(time.monotonic() - start)
                        count += 1
                        break
                    except ObjNotFoundError:
                        # hex form is nicer to read
                        objid_hex = {k: cast(bytes, v).hex() for k, v in objid.items()}
                        # convert to a frozenset of tuples as dicts are not hashable
                        not_found.add(frozenset(objid_hex.items()))
                        logger.debug(
                            "%s not found in objstorage “%s” for deletion",
                            objid_hex,
                            name,
                        )
                        break
                    except ObjstorageError as e:
                        raise e
                    except Exception as e:
                        if attempt >= OBJSTORAGE_DELETE_MAX_ATTEMPTS:
                            raise e
                        else:
                            cooldown = 5 * attempt
                            logger.warning(
                                "objstorage “%s” raised “%r” during attempt %d, "
                                "retrying in %d seconds…",
                                name,
                                e,
                                attempt,
                                cooldown,
                            )
                            time.sleep(cooldown)
                    attempt += 1
        stats = (
            (
                f" Total time: {format_duration(sum(durations))},"
                f" average: {format_duration(statistics.mean(durations))} per object"
            )
            if len(durations) > 0
            else ""
        )
        stdev = (
            f", standard deviation: {format_duration(statistics.stdev(durations))}"
            if len(durations) >= 2
            else ""
        )
        _secho(
            f"{count} objects removed from objstorage “{name}”.{stats}{stdev}",
            fg="green",
        )
        return not_found

    def have_new_references(self, removed_swhids: List[ExtendedSWHID]) -> bool:
        """Find out if any removed objects now have a new references coming from
        an object outside the set of removed objects."""

        swhids = set(removed_swhids)
        with self.progressbar(
            swhids, label="Looking for newly added references…"
        ) as bar:
            for swhid in bar:
                if swhid.object_type == ExtendedObjectType.ORIGIN:
                    continue
                recent_references = get_filtered_objects(
                    self.storage,
                    partial(self.storage.object_find_recent_references, swhid),
                    len(swhids) + 1,
                )
                if not swhids.issuperset(set(recent_references)):
                    return True
        return False

    @staticmethod
    def _get_info_from_masking_request(
        masking_request: MaskingRequest,
    ) -> Dict[str, Any]:
        match = re.search(
            r"^---\n.*", masking_request.reason, flags=re.MULTILINE | re.DOTALL
        )
        if not match:
            raise ValueError("Unable to find marker lines in masking request’s reason")
        return yaml.safe_load(match.group(0))

    @staticmethod
    def _get_requested_from_masking_request(
        requested: List[str],
    ) -> Iterator[Origin | ExtendedSWHID]:
        for s in requested:
            if s.startswith("swh:1:"):
                yield ExtendedSWHID.from_string(s)
            else:
                yield Origin(url=s)

    def handle_removal_notification_with_removal(
        self,
        notification_removal_identifier: str,
        secret_sharing: SecretSharing,
        recovery_bundle_path: str,
        ignore_requested=List[Origin | ExtendedSWHID],
        allow_empty_content_objects: bool = False,
        recompute_swhids_to_remove: bool = True,
    ) -> None:
        assert self.masking_admin is not None

        masking_request_slug = (
            f"{MASKING_REQUEST_IDENTIFIER_PREFIX}{notification_removal_identifier}"
        )
        # Recover data required to perform removal
        with self.masking_admin.conn:
            masking_request = self.masking_admin.find_request(masking_request_slug)
            if masking_request is None:
                raise MaskingRequestNotFound(masking_request_slug)
            info = self._get_info_from_masking_request(masking_request)
            requested = list(
                set(self._get_requested_from_masking_request(info["requested"]))
                - set(ignore_requested)
            )
            requested_swhids = [
                o.swhid() if isinstance(o, Origin) else o for o in requested
            ]
            # XXX should we add a flag to remove all of them?
            masking_states = self.masking_admin.get_states_for_request(
                masking_request.id
            )
            decision_pending_swhids = {
                swhid
                for swhid, state in masking_states.items()
                if state == MaskedState.DECISION_PENDING
            }

        # Perform removal
        if recompute_swhids_to_remove:
            try:
                removable = self.get_removable(requested_swhids)
            except RootsNotFound as e:
                _secho(
                    "Some requested objects were not found:",
                    err=True,
                    fg="red",
                    bold=True,
                )
                for label in e.get_labels(requested):
                    _secho(f"- {label}", err=True)
                raise
        else:
            removable = Removable(
                removable_swhids=list(decision_pending_swhids),
                referencing=requested_swhids,
            )

        decryption_key = self.create_recovery_bundle(
            secret_sharing=secret_sharing,
            requested=requested,
            removable=removable,
            recovery_bundle_path=recovery_bundle_path,
            removal_identifier=masking_request_slug,
            reason=info["reason"],
            allow_empty_content_objects=allow_empty_content_objects,
        )
        _secho(f"Recovery bundle decryption key: {decryption_key}", fg="blue")
        try:
            self.remove()
        except Exception as e:
            _secho(str(e), err=True, fg="red", bold=True)
            _secho("Rolling back…", fg="cyan")
            self.restore_recovery_bundle()
            raise

        # Clear removed objects in masking db
        recovery_bundle = RecoveryBundle(recovery_bundle_path)
        removed_swhids = recovery_bundle.swhids
        with self.masking_admin.conn:
            leftover_swhids = decision_pending_swhids - set(removed_swhids)
            record = f"Made {len(removed_swhids)} objects visible again after removal."
            if leftover_swhids:
                record += (
                    "\n\nObjects in state “decision pending” that were not removed:\n"
                )
                record += "\n".join(f"- {swhid}" for swhid in leftover_swhids)
            self.masking_admin.set_object_state(
                masking_request.id, MaskedState.VISIBLE, recovery_bundle.swhids
            )
            self.masking_admin.record_history(masking_request.id, record)

    def handle_removal_notification_by_changing_masked_status(
        self,
        notification_removal_identifier: str,
        masked_state: MaskedState,
    ):
        assert self.masking_admin is not None

        masking_request_slug = (
            f"{MASKING_REQUEST_IDENTIFIER_PREFIX}{notification_removal_identifier}"
        )
        with self.masking_admin.conn:
            masking_request = self.masking_admin.find_request(masking_request_slug)
            if masking_request is None:
                raise MaskingRequestNotFound(masking_request_slug)
            masking_states = self.masking_admin.get_states_for_request(
                masking_request.id
            )
            swhids = list(masking_states.keys())
            self.masking_admin.set_object_state(
                masking_request.id,
                masked_state,
                swhids,
            )
            match masked_state:
                case MaskedState.RESTRICTED:
                    masked_state_label = "permanently restricted"
                case MaskedState.VISIBLE:
                    masked_state_label = "visible again"
                case MaskedState.DECISION_PENDING:
                    masked_state_label = "restricted until a decision is made"
            record = f"Made {len(swhids)} objects {masked_state_label}."
            self.masking_admin.record_history(masking_request.id, record)
