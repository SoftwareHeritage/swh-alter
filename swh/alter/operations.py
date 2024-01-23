# Copyright (C) 2023 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import collections
from datetime import datetime
import logging
from typing import Dict, List, Optional, TextIO, Union, cast

from swh.graph.http_client import RemoteGraphClient
from swh.journal.writer.kafka import KafkaJournalWriter
from swh.model.model import Content, KeyType
from swh.model.swhids import CoreSWHID, ExtendedObjectType, ExtendedSWHID
from swh.objstorage.exc import ObjNotFoundError
from swh.objstorage.interface import (
    CompositeObjId,
    ObjStorageInterface,
    objid_from_dict,
)
from swh.storage.interface import ObjectDeletionInterface, StorageInterface

from .inventory import make_inventory
from .recovery_bundle import (
    AgeSecretKey,
    HasSwhid,
    HasUniqueKey,
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


class Remover:
    """Helper class used to perform a removal."""

    def __init__(
        self,
        /,
        storage: StorageInterface,
        graph_client: RemoteGraphClient,
        restoration_storage: Optional[StorageInterface] = None,
        removal_storages: Optional[Dict[str, ObjectDeletionInterface]] = None,
        removal_objstorages: Optional[Dict[str, ObjStorageInterface]] = None,
        removal_journals: Optional[Dict[str, KafkaJournalWriter]] = None,
    ):
        self.storage = storage
        self.graph_client = graph_client
        self.restoration_storage = restoration_storage
        self.removal_storages = removal_storages if removal_storages else {}
        self.removal_objstorages = removal_objstorages if removal_objstorages else {}
        self.removal_journals = removal_journals if removal_journals else {}
        self.recovery_bundle_path: Optional[str] = None
        self.object_secret_key: Optional[AgeSecretKey] = None
        self.swhids_to_remove: List[ExtendedSWHID] = []
        self.objids_to_remove: List[CompositeObjId] = []
        self.journal_objects_to_remove: Dict[
            str, List[KeyType]
        ] = collections.defaultdict(list)

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
        _secho("Inventorying all reachable objects…", fg="cyan")
        inventory_subgraph = make_inventory(self.storage, self.graph_client, swhids)
        if output_inventory_subgraph:
            inventory_subgraph.write_dot(output_inventory_subgraph)
            output_inventory_subgraph.close()
        _secho("Determining which objects can be safely removed…", fg="cyan")
        removable_subgraph = mark_removable(
            self.storage, self.graph_client, inventory_subgraph
        )
        if output_removable_subgraph:
            removable_subgraph.write_dot(output_removable_subgraph)
            output_removable_subgraph.close()
        removable_subgraph.delete_unremovable()
        if output_pruned_removable_subgraph:
            removable_subgraph.write_dot(output_pruned_removable_subgraph)
            output_pruned_removable_subgraph.close()
        return list(removable_subgraph.removable_swhids())

    def register_object(self, obj: Union[HasSwhid, HasUniqueKey]) -> None:
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
        self.journal_objects_to_remove[obj.object_type].append(obj.unique_key())

    def create_recovery_bundle(
        self,
        /,
        secret_sharing: SecretSharing,
        removable_swhids: List[ExtendedSWHID],
        recovery_bundle_path: str,
        removal_identifier: str,
        reason: Optional[str] = None,
        expire: Optional[datetime] = None,
    ) -> None:
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
            creator.backup_swhids(removable_swhids)
        self.recovery_bundle_path = recovery_bundle_path
        _secho("Recovery bundle created.", fg="green")

    def restore_recovery_bundle(self) -> None:
        assert self.restoration_storage
        assert self.recovery_bundle_path

        def key_provider(_):
            assert self.object_secret_key
            return self.object_secret_key

        _secho("Restoring recovery bundle…", fg="cyan")
        bundle = RecoveryBundle(self.recovery_bundle_path, key_provider)
        result = bundle.restore(self.restoration_storage)
        total = sum(result.values())
        _secho(f"{total} objects restored.", fg="green")
        if len(self.journal_objects_to_remove) != total:
            _secho(
                f"{len(self.journal_objects_to_remove)} objects should have "
                "been restored. Something might be wrong!",
                fg="red",
                bold=True,
            )

    def remove(self) -> None:
        for name, removal_storage in self.removal_storages.items():
            _secho(f"Removing objects from storage “{name}”…", fg="cyan")
            result = removal_storage.object_delete(self.swhids_to_remove)
            _secho(
                f"{sum(result.values())} objects removed from storage “{name}”.",
                fg="green",
            )

        for name, removal_objstorage in self.removal_objstorages.items():
            self.remove_from_objstorage(name, removal_objstorage)

        for name, journal_writer in self.removal_journals.items():
            _secho(f"Removing objects from journal “{name}”…", fg="cyan")
            for object_type, keys in self.journal_objects_to_remove.items():
                journal_writer.delete(object_type, keys)
            journal_writer.flush()
            _secho(f"Objects removed from journal “{name}”.", fg="green")

        if self.have_new_references(self.swhids_to_remove):
            raise RemoverError("New references have been added to removed objects")

    def remove_from_objstorage(
        self, name: str, objstorage: ObjStorageInterface
    ) -> None:
        _secho(f"Removing objects from objstorage “{name}”…", fg="cyan")
        count = 0
        for objid in self.objids_to_remove:
            try:
                objstorage.delete(objid)
                count += 1
            except ObjNotFoundError:
                _secho(
                    f"{objid} not found in objstorage “{name}” for deletion", fg="red"
                )
        _secho(f"{count} objects removed from objstorage “{name}”.", fg="green")

    def have_new_references(self, removed_swhids: List[ExtendedSWHID]) -> bool:
        """Find out if any removed objects now have a new references coming from
        an object outside the set of removed objects."""

        swhids = set(removed_swhids)
        for swhid in swhids:
            if swhid.object_type == ExtendedObjectType.ORIGIN:
                continue
            recent_references = self.storage.object_find_recent_references(
                swhid, 9_999_999
            )
            if not swhids.issuperset(set(recent_references)):
                return True
        return False
