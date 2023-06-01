# Copyright (C) 2023 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import logging
from typing import Any, Dict, List, TextIO

from igraph import Graph, Vertex

from swh.model.swhids import CoreSWHID
from swh.model.swhids import ExtendedObjectType as ObjectType
from swh.model.swhids import ExtendedSWHID

logger = logging.getLogger(__name__)


# Only used when generating graphviz output
def _batched(it, n):
    from itertools import islice

    # TODO: Migrate to the the assignment syntax once we require Python 3.8+
    # while batch := tuple(islice(it, n)):
    #     yield batch
    while True:
        batch = tuple(islice(it, n))
        if not batch:
            return
        yield batch


class Subgraph(Graph):
    """A class to hold a small subset of the Software Heritage graph

    Each vertex corresponds to a single SWHID and vice versa. The graph is
    directed and each edge represents a reference from an object in Software
    Heritage storage to another.

    This is backed by the `igraph <https://igraph.org/>`_ library for
    convenience.

    This class is intended to be subclassed to implement the more specific
    behaviors needed for the different stage of the :ref:`object removal
    algorithm <alter_removal_algorithm>`.
    """

    def __init__(self, *args, **kwargs):
        """See also `igraph.Graph constructor
        <https://igraph.org/python/api/latest/igraph.Graph.html#__init__>`_"""
        super().__init__(*args, directed=True, **kwargs)
        if "name" not in self.vs.attributes():
            self.vs["name"] = []
        if "swhid" not in self.vs.attributes():
            self.vs["swhid"] = []

    @classmethod
    def copy(cls, subgraph):
        """Create a new instance by copying vertices, edges and respective
        attributes from the given subgraph."""
        g = subgraph
        return cls(
            n=len(g.vs),
            edges=(e.tuple for e in g.es),
            graph_attrs={attr: g[attr] for attr in g.attributes()},
            vertex_attrs={attr: g.vs[attr] for attr in g.vs.attributes()},
            edge_attrs={attr: g.es[attr] for attr in g.es.attributes()},
        )

    # Used by select_ordered() below
    _OBJECT_TYPE_ORDER = {
        t: v
        for v, t in enumerate(
            [
                ObjectType.ORIGIN,
                ObjectType.SNAPSHOT,
                ObjectType.RELEASE,
                ObjectType.REVISION,
                ObjectType.DIRECTORY,
                ObjectType.CONTENT,
            ]
        )
    }

    default_vertex_attributes: Dict[str, Any] = {}
    """Vertex will get the following attributes on creation
    unless specified otherwise."""

    def add_vertex(self, name: str, **kwargs) -> Vertex:
        """Add or update a vertex.

        A vertex with the given `name` will be created if it does not exist already.

        Attributes for the vertex will be set to the one given as keyword arguments.

        Returns:
            a Vertex object corresponding to the added or updated vertex
        """
        try:
            # The name attribute is indexed. See:
            # https://lists.nongnu.org/archive/html/igraph-help/2014-05/msg00069.html
            v = self.vs.find(name)
            v.update_attributes(**kwargs)
            return v
        except ValueError:
            for k, v in type(self).default_vertex_attributes.items():
                kwargs[k] = kwargs.get(k, v)
            return super().add_vertex(name, source=set(), **kwargs)

    def add_swhid(self, object_or_swhid, **kwargs) -> Vertex:
        """Add or update a vertex for the given SWHID or object.

        This is a convenience method to add vertex from either :py:class:`CoreSWHID`,
        :py:class:`ExtendedSWHID`, or any objects implementing a ``swhid()`` method
        returning one of those.
        """
        if hasattr(object_or_swhid, "swhid") and callable(object_or_swhid.swhid):
            swhid = object_or_swhid.swhid()
        else:
            swhid = object_or_swhid
        if type(swhid) is CoreSWHID:
            swhid = swhid.to_extended()
        elif type(swhid) is str:
            swhid = ExtendedSWHID.from_string(swhid)
        return self.add_vertex(name=str(swhid), swhid=swhid, **kwargs)

    def swhids(self) -> List[ExtendedSWHID]:
        """Returns all SWHID in this subgraph"""
        return self.vs["swhid"]

    _DEBUG_EDGE_INSERTION = False

    def add_edge(self, src: Vertex, dst: Vertex, skip_duplicates=False, **kwargs):
        """Add an edge with the given attributes.

        When trying to add an edge that already exists:
        - if `skip_duplicates` is set to True, nothing will be done,
        - otherwise (the default), an exception will be raised.

        Raises:
            ValueError if the given edge already exists and `skip_duplicates` is False
        """
        if self.get_eid(src, dst, error=False) != -1:
            if skip_duplicates:
                return

            import inspect

            current_frame = inspect.currentframe()
            if current_frame and current_frame.f_back:
                caller = inspect.getframeinfo(current_frame.f_back)[2]
            else:
                caller = "<unknown>"
            raise ValueError(
                "Duplicate edge %s → %s, added from %s"
                % (src["name"], dst["name"], caller)
            )
        # This will also log edge insertion in the graph, making for a very
        # verbose output. It should only be useful if you get the
        # “duplicate edge” above.
        if False:
            import inspect

            logger.debug(
                "Inserting edge %s → %s, added from %s",
                src["name"],
                dst["name"],
                inspect.getframeinfo(inspect.currentframe().f_back)[2].strip(),
            )
        super().add_edge(src, dst, **kwargs)

    def select_ordered(self, *args, **kwargs) -> List[Vertex]:
        """Get vertices ordered by object type from origins to contents"""
        return sorted(
            self.vs.select(*args, **kwargs),
            key=lambda v: Subgraph._OBJECT_TYPE_ORDER[v["swhid"].object_type],
        )

    def _format_swhid_label(self, s):
        """Format SWHID taking only SHA1 and breaking in lines of 8 characters"""
        return "\\n".join(
            ["".join(batch) for batch in _batched(iter(s.split(":")[3]), 8)]
        )

    def dot_node_attributes(self, v: Vertex) -> List[str]:
        """Get a list of attributes in DOT format for the given vertex.

        The default implementation defines a label with a formatted SWHID.
        This method is called by :py:meth:`write_dot` and is meant to be
        subclassed to produce extra labels to highlight certain graph aspects.
        """
        return [f'label="{self._format_swhid_label(v["name"])}"']

    def write_dot(self, f: TextIO) -> None:
        """Write a representation of this subgraph in DOT format to `f`.

        The result can be processed using the `dot` command-line utility provided
        by the Graphviz package.
        """

        def write_objects(f, object_type):
            for v in self.vs.select(lambda v: v["swhid"].object_type == object_type):
                f.write(f'    {v.index} [{", ".join(self.dot_node_attributes(v))}];\n')
                for dst in v.successors():
                    # layout rev -> rev edges horizontally
                    if (
                        v["swhid"].object_type == ObjectType.REVISION
                        and dst["swhid"].object_type == ObjectType.REVISION
                    ):
                        edge_options = " [constraint=false]"
                    else:
                        edge_options = ""
                    f.write(f"    {v.index} -> {dst.index}{edge_options};\n")

        f.write(
            f'digraph "{self["name"] if "name" in self.attributes() else "Subgraph"}"'
            "{\n"
            "  ranksep=1; nodesep=0.5;\n"
            "  subgraph cnt {\n"
            "    node [style=filled, fillcolor=pink];\n"
        )
        write_objects(f, ObjectType.CONTENT)
        f.write(
            "  }\n"
            "  subgraph cluster_dir {\n"
            '    label="File contents";\n'
            "    node [shape=folder, style=filled, fillcolor=lightblue];\n"
        )
        write_objects(f, ObjectType.DIRECTORY)
        f.write(
            "  }\n"
            "  subgraph cluster_rev {\n"
            '    label="Revisions";\n'
            "    node [shape=diamond, style=filled, fillcolor=orchid];\n"
        )
        write_objects(f, ObjectType.REVISION)
        f.write(
            "  }\n"
            "  subgraph cluster_rel {\n"
            '    label="Releases";\n'
            "    node [shape=octagon, style=filled, fillcolor=sandybrown];\n"
        )
        write_objects(f, ObjectType.RELEASE)
        f.write(
            "  }\n"
            "  subgraph cluster_snp {\n"
            '    label="Snapshot";\n'
            "    node [shape=doubleoctagon, style=filled, fillcolor=aqua];\n"
        )
        write_objects(f, ObjectType.SNAPSHOT)
        f.write(
            "  }\n"
            "  subgraph cluster_ori {\n"
            '    label="Origins";\n'
            "    node [shape=egg, style=filled, fillcolor=khaki];\n"
        )
        write_objects(f, ObjectType.ORIGIN)
        f.write("  }\n}\n")
