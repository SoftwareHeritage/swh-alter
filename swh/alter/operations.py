# Copyright (C) 2023 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import collections
from datetime import datetime
import itertools
import logging
from typing import Dict, List, Optional, TextIO, Tuple, cast

from swh.core.utils import grouper
from swh.graph.http_client import RemoteGraphClient
from swh.journal.writer.kafka import KafkaJournalWriter
from swh.model.model import BaseModel, Content, KeyType, Origin
from swh.model.swhids import CoreSWHID, ExtendedObjectType, ExtendedSWHID
from swh.model.swhids import ObjectType as CoreSWHIDObjectType
from swh.objstorage.exc import ObjNotFoundError
from swh.objstorage.interface import (
    CompositeObjId,
    ObjStorageInterface,
    objid_from_dict,
)
from swh.search.interface import SearchInterface
from swh.storage.interface import ObjectDeletionInterface, StorageInterface

from .inventory import get_raw_extrinsic_metadata, make_inventory
from .progressbar import ProgressBar, ProgressBarInit, no_progressbar
from .recovery_bundle import (
    AgeSecretKey,
    RecoveryBundle,
    RecoveryBundleCreator,
    SecretSharing,
    generate_age_keypair,
)
from .removable import mark_removable

logger = logging.getLogger(__name__)


class RemoverError(Exception):
    pass


def _secho(msg, **kwargs):
    """Log at info level, passing kwargs as styles for click.secho()"""
    logger.info(msg, extra={"style": kwargs})


STORAGE_OBJECT_DELETE_CHUNK_SIZE = 200
RECOVERY_BUNDLE_BACKUP_SWHIDS_CHUNK_SIZE = 200


class Remover:
    """Helper class used to perform a removal."""

    def __init__(
        self,
        /,
        storage: StorageInterface,
        graph_client: RemoteGraphClient,
        restoration_storage: Optional[StorageInterface] = None,
        removal_searches: Optional[Dict[str, SearchInterface]] = None,
        removal_storages: Optional[Dict[str, ObjectDeletionInterface]] = None,
        removal_objstorages: Optional[Dict[str, ObjStorageInterface]] = None,
        removal_journals: Optional[Dict[str, KafkaJournalWriter]] = None,
        progressbar: Optional[ProgressBarInit] = None,
    ):
        self.storage = storage
        self.graph_client = graph_client
        self.restoration_storage = restoration_storage
        self.removal_searches = removal_searches if removal_searches else {}
        self.removal_storages = removal_storages if removal_storages else {}
        self.removal_objstorages = removal_objstorages if removal_objstorages else {}
        self.removal_journals = removal_journals if removal_journals else {}
        self.recovery_bundle_path: Optional[str] = None
        self.object_secret_key: Optional[AgeSecretKey] = None
        self.swhids_to_remove: List[ExtendedSWHID] = []
        self.objids_to_remove: List[CompositeObjId] = []
        self.origin_urls_to_remove: List[str] = []
        self.journal_objects_to_remove: Dict[
            str, List[KeyType]
        ] = collections.defaultdict(list)
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
    ) -> List[ExtendedSWHID]:
        _secho("Removing the following origins:")
        for swhid in swhids:
            _secho(f" - {swhid}")
        _secho("Finding removable objects…", fg="cyan")
        inventory_subgraph = make_inventory(
            self.storage, self.graph_client, swhids, self.progressbar
        )
        if output_inventory_subgraph:
            inventory_subgraph.write_dot(output_inventory_subgraph)
            output_inventory_subgraph.close()
        removable_subgraph = mark_removable(
            self.storage, self.graph_client, inventory_subgraph, self.progressbar
        )
        if output_removable_subgraph:
            removable_subgraph.write_dot(output_removable_subgraph)
            output_removable_subgraph.close()
        removable_subgraph.delete_unremovable()
        if output_pruned_removable_subgraph:
            removable_subgraph.write_dot(output_pruned_removable_subgraph)
            output_pruned_removable_subgraph.close()
        removable_swhids = list(removable_subgraph.removable_swhids())
        removable_swhids.extend(
            get_raw_extrinsic_metadata(self.storage, removable_swhids)
        )
        return removable_swhids

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
    ):
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

    def create_recovery_bundle(
        self,
        /,
        secret_sharing: SecretSharing,
        removable_swhids: List[ExtendedSWHID],
        recovery_bundle_path: str,
        removal_identifier: str,
        reason: Optional[str] = None,
        expire: Optional[datetime] = None,
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
            object_public_key=object_public_key,
            decryption_key_shares=decryption_key_shares,
            registration_callback=self.register_object,
        ) as creator:
            if reason is not None:
                creator.set_reason(reason)
            if expire is not None:
                try:
                    creator.set_expire(expire)
                except ValueError as ex:
                    raise RemoverError(f"Unable to set expiration date: {str(ex)}")
            bar: ProgressBar[int]
            with self.progressbar(
                length=len(removable_swhids), label="Backing up objects…"
            ) as bar:
                for chunk in grouper(
                    removable_swhids, RECOVERY_BUNDLE_BACKUP_SWHIDS_CHUNK_SIZE
                ):
                    swhid_count = creator.backup_swhids(chunk)
                    bar.update(n_steps=swhid_count)
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
        for name, removal_objstorage in self.removal_objstorages.items():
            self.remove_from_objstorage(name, removal_objstorage)
        if self.have_new_references(self.swhids_to_remove):
            raise RemoverError("New references have been added to removed objects")

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

    def remove_from_objstorage(
        self, name: str, objstorage: ObjStorageInterface
    ) -> None:
        count = 0
        with self.progressbar(
            self.objids_to_remove, label=f"Removing objects from objstorage “{name}”…"
        ) as bar:
            for objid in bar:
                try:
                    objstorage.delete(objid)
                    count += 1
                except ObjNotFoundError:
                    _secho(
                        f"{objid} not found in objstorage “{name}” for deletion",
                        fg="red",
                    )
        _secho(f"{count} objects removed from objstorage “{name}”.", fg="green")

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
                recent_references = self.storage.object_find_recent_references(
                    swhid, 9_999_999
                )
                if not swhids.issuperset(set(recent_references)):
                    return True
        return False
