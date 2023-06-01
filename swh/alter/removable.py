# Copyright (C) 2023 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

"""
This module implements the marking stage of the
:ref:`removal algorithm <alter_removal_algorithm>`.
"""

from enum import Enum, auto
from itertools import chain
import logging
from typing import Iterator, List

from igraph import Vertex

from swh.graph.http_client import GraphArgumentException, RemoteGraphClient
from swh.model.swhids import ExtendedObjectType as ObjectType
from swh.model.swhids import ExtendedSWHID
from swh.storage.interface import StorageInterface

from .inventory import InventorySubgraph
from .subgraph import Subgraph

logger = logging.getLogger(__name__)


class MarkingState(Enum):
    """Represents the different state of vertices while the marking algorithm is on-going.

    All vertices start UNMARKED. After examination of their inbound references, they are
    either marked as REMOVABLE or UNREMOVABLE.

    :meta private:
    """

    UNMARKED = auto()
    REMOVABLE = auto()
    UNREMOVABLE = auto()


class RemovableSubgraph(Subgraph):
    """A class representing the subgraph of objects that can be safely removed
    from the archive

    This subgraph should only be created from an :py:class:`InventorySubgraph`
    using :py:meth:`from_inventory_subgraph`. No new vertices or edges can be
    added at this point.

    Getting the list of SWHID that can be removed is done by using
    py:meth:`removable_swhids`.

    After marking happened, this subgraph will contain all candidates until
    :py:meth:`delete_unremovable` is called.
    """

    def __init__(self, *args, **kwargs):
        """ """
        super().__init__(*args, **kwargs)
        self["name"] = "Removable"
        self.vs["state"] = MarkingState.UNMARKED

    @classmethod
    def from_inventory_subgraph(cls, subgraph: InventorySubgraph):
        return cls.copy(subgraph)

    def add_vertex(self, name: str, **kwargs):
        """Not available for RemovableSubgraph.

        :meta private:"""
        raise NotImplementedError("No new vertex should be added at this stage.")

    def add_edge(self, src: Vertex, dst: Vertex, skip_duplicates=False, **kwargs):
        """Not available for RemovableSubgraph.

        :meta private:"""
        raise NotImplementedError("No new edge should be added at this stage.")

    def delete_unremovable(self):
        """Delete all vertices for unremovable objects from this subgraph."""

        self.delete_vertices(self.vs.select(state_eq=MarkingState.UNREMOVABLE))

    def removable_swhids(self) -> List[ExtendedSWHID]:
        """Returns a list of SWHIDs that can safely be removed from the archive."""

        return [
            v["swhid"] for v in self.select_ordered(state_eq=MarkingState.REMOVABLE)
        ]

    def dot_node_attributes(self, v: Vertex) -> List[str]:
        """Get a list of attributes in DOT format for the given vertex.

        On top of default attributes, color the background of each node if
        they can be removed or not.

        :meta private:
        """
        attrs = super().dot_node_attributes(v)
        # Unset the shape so we can better spot ExtendedSWHID that can be removed
        if v["state"] == MarkingState.UNMARKED:
            attrs.append('style="filled,dotted"')
        elif v["state"] == MarkingState.UNREMOVABLE:
            attrs.append("fillcolor=white")
        else:
            attrs.append("fillcolor=red")
        return attrs


class Marker:
    """A class encapsulating our algorithm marking nodes as removable or not.

    :meta private:
    """

    def __init__(
        self,
        storage: StorageInterface,
        graph_client: RemoteGraphClient,
        subgraph: RemovableSubgraph,
    ):
        self._storage = storage
        self._graph_client = graph_client
        self._subgraph = subgraph
        if logger.isEnabledFor(logging.INFO):
            self._total_nodes = len(subgraph.vs)
            self._marked_count = 0

    @property
    def subgraph(self):
        return self._subgraph

    def has_unknown_inbound_edges(self, vertex: Vertex):
        # Origins never have any inbound edges
        if vertex["swhid"].object_type == ObjectType.ORIGIN:
            return False
        # We use a set of str as an optimization because
        # swh.graph API will return SWHIDs as str
        known_predecessors = {str(pred["swhid"]) for pred in vertex.predecessors()}
        # We only need to find one extra edge from the ones we already know
        search_limit = len(known_predecessors) + 1
        for pred in chain(
            self.inbound_edges_from_graph(vertex, search_limit),
            self.inbound_edges_from_storage(vertex, search_limit),
        ):
            # Removing a revision used as a submodule should be possible.
            # (We do not care that it will make submodule users miss part
            # of their source code.)
            # We use string matching here because the graph API returns
            # str objects and not ExtendedSWHID objects.
            if vertex["swhid"].object_type == ObjectType.REVISION and pred.startswith(
                "swh:1:dir:"
            ):
                logger.info(
                    "Skipping predecessor %s of %s as its a submodule",
                    pred,
                    vertex["swhid"],
                )
                return False
            logger.debug("Is %s an extra predecessor of %s?", pred, vertex["swhid"])
            if pred not in known_predecessors:
                return True
        return False

    def inbound_edges_from_graph(
        self, vertex: Vertex, search_limit: int
    ) -> Iterator[str]:
        try:
            yield from self._graph_client.neighbors(
                str(vertex["swhid"]), direction="backward", max_edges=search_limit
            )
        except GraphArgumentException:
            yield from ()

    def inbound_edges_from_storage(
        self, vertex: Vertex, search_limit: int
    ) -> Iterator[str]:
        yield from map(
            str,
            self._storage.object_find_recent_references(
                vertex["swhid"], limit=search_limit
            ),
        )

    def mark_candidates(self):
        for index, vid in enumerate(self._subgraph.topological_sorting()):
            with open("mark-%02d.dot" % index, "w") as f:
                self._subgraph.write_dot(f)
            vertex = self._subgraph.vs[vid]
            assert all(
                pred["state"] != MarkingState.UNMARKED for pred in vertex.predecessors()
            ), "topological sort broken: one predecessor is still in unmarked state"
            # If any predecessor is unremovable, this makes this object unremovable too
            if any(
                pred["state"] == MarkingState.UNREMOVABLE
                for pred in vertex.predecessors()
            ):
                vertex["state"] = MarkingState.UNREMOVABLE
                continue
            vertex["state"] = (
                MarkingState.UNREMOVABLE
                if self.has_unknown_inbound_edges(vertex)
                else MarkingState.REMOVABLE
            )
            self.log_marking_progress()

    def log_marking_progress(self):
        if not logger.isEnabledFor(logging.INFO):
            return
        self._marked_count += 1
        if self._total_nodes == self._marked_count or self._marked_count % 100 == 0:
            logger.info(
                "Checking inbound edges for node %s/%s",
                self._marked_count,
                self._total_nodes,
            )


def mark_removable(
    storage: StorageInterface,
    graph_client: RemoteGraphClient,
    inventory_subgraph: InventorySubgraph,
) -> RemovableSubgraph:
    """Find which candidates can be safely removed from the archive.

    Using the previously populated ``inventory_subgraph``, query the given
    ``storage`` and ``graph_client`` to assess inbound references for each
    candidate and see which one can be safely removed from the archive.
    """
    subgraph = RemovableSubgraph.from_inventory_subgraph(inventory_subgraph)
    marker = Marker(storage, graph_client, subgraph)
    marker.mark_candidates()
    return marker.subgraph
