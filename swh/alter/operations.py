# Copyright (C) 2023 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import collections
from datetime import datetime
import logging
from typing import Dict, List, Optional, Protocol, TextIO, Union

from swh.graph.http_client import RemoteGraphClient
from swh.journal.writer.kafka import KafkaJournalWriter
from swh.model.model import KeyType
from swh.model.swhids import CoreSWHID, ExtendedObjectType, ExtendedSWHID
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


class StorageWithDelete(StorageInterface, ObjectDeletionInterface, Protocol):
    pass


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
        storage: StorageWithDelete,
        graph_client: RemoteGraphClient,
        journal_writer: Optional[KafkaJournalWriter] = None,
        extra_storages: Optional[Dict[str, ObjectDeletionInterface]] = None,
    ):
        self.storage = storage
        self.graph_client = graph_client
        self.journal_writer = journal_writer
        self.extra_storages = extra_storages if extra_storages else {}
        self.recovery_bundle_path: Optional[str] = None
        self.object_secret_key: Optional[AgeSecretKey] = None
        self.swhids_to_remove: List[ExtendedSWHID] = []
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
            swhid = obj.swhid()
            if swhid is not None:
                if isinstance(swhid, CoreSWHID):
                    self.swhids_to_remove.append(swhid.to_extended())
                else:
                    self.swhids_to_remove.append(swhid)
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
        assert self.recovery_bundle_path

        def key_provider(_):
            assert self.object_secret_key
            return self.object_secret_key

        _secho("Restoring recovery bundle…", fg="cyan")
        bundle = RecoveryBundle(self.recovery_bundle_path, key_provider)
        result = bundle.restore(self.storage)
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
        _secho("Removing objects from primary storage…", fg="cyan")
        result = self.storage.object_delete(self.swhids_to_remove)
        _secho(
            f"{sum(result.values())} objects removed from primary storage.", fg="green"
        )

        for name, extra_storage in self.extra_storages.items():
            _secho(f"Removing objects from storage “{name}”…", fg="cyan")
            result = extra_storage.object_delete(self.swhids_to_remove)
            _secho(
                f"{sum(result.values())} objects removed from storage “{name}”.",
                fg="green",
            )

        if self.journal_writer:
            _secho("Removing objects from the journal…", fg="cyan")
            for object_type, keys in self.journal_objects_to_remove.items():
                self.journal_writer.delete(object_type, keys)
            self.journal_writer.flush()
            _secho("Objects removed from the journal.", fg="green")

        if self.have_new_references(self.swhids_to_remove):
            raise RemoverError("New references have been added to removed objects")

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
