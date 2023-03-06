# Copyright (C) 2023 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import shutil

import pytest

import swh.graph.example_dataset as graph_dataset
from swh.model.swhids import ExtendedObjectType as ObjectType

from ..subgraph import Subgraph


def write_dot_if_requested(subgraph, filename):
    import os
    from pathlib import Path

    if "SWH_ALTER_TESTS_DOT_OUTPUT_DIR" in os.environ:
        with (Path(os.environ["SWH_ALTER_TESTS_DOT_OUTPUT_DIR"]) / filename).open(
            "w"
        ) as f:
            subgraph.write_dot(f)


@pytest.fixture
def empty_subgraph():
    return Subgraph()


@pytest.fixture
def sample_data_subgraph(empty_subgraph):
    g = empty_subgraph
    for content in graph_dataset.CONTENTS:
        g.add_swhid(content)
    for skipped_content in graph_dataset.SKIPPED_CONTENTS:
        g.add_swhid(skipped_content)
    for directory in graph_dataset.DIRECTORIES:
        source = g.add_swhid(directory)
        targets = [g.add_swhid(entry) for entry in directory.entries]
        g.add_edges([(source, target) for target in targets])
    for revision in graph_dataset.REVISIONS:
        source = g.add_swhid(revision)
        targets = []
        targets.append(g.add_swhid(revision.directory_swhid()))
        for parent_swhid in revision.parent_swhids():
            targets.append(g.add_swhid(parent_swhid))
        g.add_edges([(source, target) for target in targets])
    for release in graph_dataset.RELEASES:
        if str(release.swhid()) == "swh:1:rel:0000000000000000000000000000000000000019":
            # Skip the dangling swh:rel:…019 (not connected to any origin)
            continue
        source = g.add_swhid(release)
        target = g.add_swhid(release.target_swhid())
        g.add_edges([(source, target)])
    for snapshot in graph_dataset.SNAPSHOTS:
        source = g.add_swhid(snapshot)
        targets = []
        for branch in snapshot.branches.values():
            if not branch:  # skip dangling branches
                continue
            target_swhid = branch.swhid()
            if target_swhid is None:
                continue
            targets.append(g.add_swhid(target_swhid))
        g.add_edges([(source, target) for target in targets])
    for origin in graph_dataset.ORIGINS:
        source = g.add_swhid(origin)
    for visit_status in graph_dataset.ORIGIN_VISIT_STATUSES:
        if visit_status.snapshot is None:
            continue
        source = g.add_swhid(visit_status.origin_swhid())
        target = g.add_swhid(visit_status.snapshot_swhid())
        g.add_edges([(source, target)])
    write_dot_if_requested(g, "sample_data_subgraph.dot")
    return g


def test_copy(sample_data_subgraph):
    new = Subgraph.copy(sample_data_subgraph)
    assert new.to_dict_dict() == sample_data_subgraph.to_dict_dict()


def test_add_vertex_insert(empty_subgraph):
    g = empty_subgraph
    v = g.add_vertex(name="a vertex", an_attr="a value", another_attr="another value")
    assert v == g.vs[v.index]
    assert v["name"] == "a vertex"
    assert v["an_attr"] == "a value"
    assert v["another_attr"] == "another value"


def test_add_vertex_on_existing_vertex(empty_subgraph):
    g = empty_subgraph
    v1 = g.add_vertex(name="a vertex")
    v2 = g.add_vertex(name="a vertex")
    assert v1 == v2
    assert len(g.vs) == 1


def test_add_vertex_on_existing_vertex_updates_attributes(empty_subgraph):
    g = empty_subgraph
    g.add_vertex(name="a vertex")
    v = g.add_vertex(name="a vertex", an_attr="a value")
    assert v["an_attr"] == "a value"
    assert g.vs.find("a vertex")["an_attr"] == "a value"


def test_add_vertex_add_defaults():
    class SubgraphWithDefaultVertexAttributes(Subgraph):
        default_vertex_attributes = {"default_attr": "default value"}

    g = SubgraphWithDefaultVertexAttributes()
    v_no_attrs = g.add_vertex(name="a vertex with no attrs")
    v_attr_set = g.add_vertex(name="a vertex with attr set", default_attr="set value")
    assert v_no_attrs["default_attr"] == "default value"
    assert v_attr_set["default_attr"] == "set value"


def test_add_vertex_complete_is_not_modified_by_unspecified_subsequent_add(
    empty_subgraph,
):
    g = empty_subgraph
    g.add_vertex(name="a vertex", complete=True)
    v = g.add_vertex(name="a vertex")
    assert v["complete"] is True


def test_add_edge_fails_on_duplicate(empty_subgraph):
    g = empty_subgraph
    v1 = g.add_vertex(name="a vertex")
    v2 = g.add_vertex(name="a vertex")
    g.add_edge(v1, v2)
    with pytest.raises(ValueError):
        g.add_edge(v1, v2)


def test_add_edge_skip_duplicates(empty_subgraph):
    g = empty_subgraph
    v1 = g.add_vertex(name="a vertex")
    v2 = g.add_vertex(name="a vertex")
    g.add_edge(v1, v2)
    g.add_edge(v1, v2, skip_duplicates=True)
    assert len(g.es) == 1


def test_select_ordered_returns_sorted_by_object_type(sample_data_subgraph):
    from itertools import groupby

    g = sample_data_subgraph
    assert [
        group[0]
        for group in groupby(g.select_ordered(), key=lambda v: v["swhid"].object_type)
    ] == [
        ObjectType.ORIGIN,
        ObjectType.SNAPSHOT,
        ObjectType.RELEASE,
        ObjectType.REVISION,
        ObjectType.DIRECTORY,
        ObjectType.CONTENT,
    ]


@pytest.mark.skipif(
    not shutil.which("gc"), reason="missing `gc` executable from graphviz"
)
def test_write_dot(sample_data_subgraph):
    from io import StringIO
    import subprocess

    f = StringIO()
    sample_data_subgraph.write_dot(f)
    completed_process = subprocess.run(
        ["gc"], input=f.getvalue().encode("utf-8"), capture_output=True
    )
    assert b"      23      27 Subgraph" in completed_process.stdout
