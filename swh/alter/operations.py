# Copyright (C) 2023 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

from datetime import datetime
import logging
from typing import Dict, List, Optional, TextIO

from swh.graph.http_client import RemoteGraphClient
from swh.model.swhids import ExtendedSWHID
from swh.storage.interface import StorageInterface

from .inventory import make_inventory
from .recovery_bundle import (
    AgeSecretKey,
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

    def __init__(self, storage: StorageInterface, graph_client: RemoteGraphClient):
        self.storage = storage
        self.graph_client = graph_client
        self.object_secret_key: Optional[AgeSecretKey] = None

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

    def create_recovery_bundle(
        self,
        /,
        secret_sharing_conf: Dict[str, str],
        removable_swhids: List[ExtendedSWHID],
        recovery_bundle_path: str,
        removal_identifier: str,
        reason: Optional[str] = None,
        expire: Optional[datetime] = None,
    ) -> None:
        object_public_key, self.object_secret_key = generate_age_keypair()
        secret_sharing = SecretSharing.from_dict(secret_sharing_conf)
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
        ) as creator:
            if reason is not None:
                creator.set_reason(reason)
            if expire is not None:
                try:
                    creator.set_expire(expire)
                except ValueError as ex:
                    raise RemoverError(f"Unable to set expiration date: {str(ex)}")
            creator.backup_swhids(removable_swhids)
        _secho("Recovery bundle created.", fg="green")

    def remove(self, swhids: List[ExtendedSWHID]) -> None:
        raise NotImplementedError("Actual removal still need to be written")
