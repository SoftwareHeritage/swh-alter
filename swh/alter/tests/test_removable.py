# Copyright (C) 2023-2024 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import pytest

import swh.graph.example_dataset as graph_dataset
from swh.graph.example_dataset import INITIAL_ORIGIN
from swh.model.swhids import ExtendedSWHID

from ..inventory import InventorySubgraph
from ..removable import mark_removable
from .conftest import write_dot_if_requested


@pytest.fixture
def inventory_from_initial_origin():
    g = InventorySubgraph()
    v_ori = g.add_swhid(INITIAL_ORIGIN.swhid())
    v_snp = g.add_swhid("swh:1:snp:0000000000000000000000000000000000000020")
    v_rel = g.add_swhid("swh:1:rel:0000000000000000000000000000000000000010")
    v_rev_09 = g.add_swhid("swh:1:rev:0000000000000000000000000000000000000009")
    v_rev_03 = g.add_swhid("swh:1:rev:0000000000000000000000000000000000000003")
    v_dir_08 = g.add_swhid("swh:1:dir:0000000000000000000000000000000000000008")
    v_dir_06 = g.add_swhid("swh:1:dir:0000000000000000000000000000000000000006")
    v_dir_02 = g.add_swhid("swh:1:dir:0000000000000000000000000000000000000002")
    v_cnt_07 = g.add_swhid("swh:1:cnt:0000000000000000000000000000000000000007")
    v_cnt_05 = g.add_swhid("swh:1:cnt:0000000000000000000000000000000000000005")
    v_cnt_04 = g.add_swhid("swh:1:cnt:0000000000000000000000000000000000000004")
    v_cnt_01 = g.add_swhid("swh:1:cnt:0000000000000000000000000000000000000001")
    g.add_edge(v_ori, v_snp)
    g.add_edge(v_snp, v_rel)
    g.add_edge(v_snp, v_rev_09)
    g.add_edge(v_rel, v_rev_09)
    g.add_edge(v_rev_09, v_rev_03)
    g.add_edge(v_rev_09, v_dir_08)
    g.add_edge(v_rev_03, v_dir_02)
    g.add_edge(v_dir_08, v_dir_06)
    g.add_edge(v_dir_08, v_cnt_07)
    g.add_edge(v_dir_08, v_cnt_01)
    g.add_edge(v_dir_06, v_cnt_05)
    g.add_edge(v_dir_06, v_cnt_04)
    g.add_edge(v_dir_02, v_cnt_01)
    write_dot_if_requested(g, "inventory_from_initial_origin.dot")
    return g


@pytest.fixture
def storage_with_no_new_references_since_export(mocker, sample_populated_storage):
    # Simulate an empty `object_references` table
    mocker.patch.object(
        sample_populated_storage,
        "object_find_recent_references",
        create=True,
        return_value=[],
    )
    return sample_populated_storage


@pytest.mark.parametrize(
    "graph_client_fixture, storage_fixture",
    [
        (
            "graph_client_with_both_origins",
            "storage_with_no_new_references_since_export",
        ),
        (
            "graph_client_with_only_initial_origin",
            "sample_populated_storage",
        ),
        (
            "graph_client_with_both_origins",
            "sample_populated_storage",
        ),
    ],
)
def test_mark_removable_on_initial_origin(
    request, storage_fixture, graph_client_fixture, inventory_from_initial_origin
):
    storage = request.getfixturevalue(storage_fixture)
    graph_client = request.getfixturevalue(graph_client_fixture)
    subgraph = mark_removable(storage, graph_client, inventory_from_initial_origin)
    # We are trying to remove the initial origin. As everything is used by the
    # fork, the only things that can be removed in the end are the corresponding
    # origin and snapshot.
    assert {str(swhid) for swhid in subgraph.removable_swhids()} == {
        "swh:1:ori:83404f995118bd25774f4ac14422a8f175e7a054",
        "swh:1:snp:0000000000000000000000000000000000000020",
    }


@pytest.mark.parametrize(
    "graph_client_fixture, storage_fixture",
    [
        (
            "graph_client_with_both_origins",
            "storage_with_no_new_references_since_export",
        ),
        (
            "graph_client_with_only_initial_origin",
            "sample_populated_storage",
        ),
        (
            "graph_client_with_both_origins",
            "sample_populated_storage",
        ),
        (
            "graph_client_with_submodule",
            # This one is not ideal as it does not contain our origin with
            # submodule. This should not matter for testing that we have
            # the right behavior in presence of submodules, though.
            "storage_with_no_new_references_since_export",
        ),
    ],
)
def test_mark_removable_on_forked_origin(
    request, storage_fixture, graph_client_fixture, inventory_from_forked_origin
):
    storage = request.getfixturevalue(storage_fixture)
    graph_client = request.getfixturevalue(graph_client_fixture)
    subgraph = mark_removable(storage, graph_client, inventory_from_forked_origin)
    # We are trying to remove the forked origin. Therefore objects coming from the
    # initial origin are unremovable. So we are left removing all objects specific
    # to the development that happened in the forked origin.
    assert {str(swhid) for swhid in subgraph.removable_swhids()} == {
        "swh:1:ori:8f50d3f60eae370ddbf85c86219c55108a350165",
        "swh:1:snp:0000000000000000000000000000000000000022",
        "swh:1:rel:0000000000000000000000000000000000000021",
        "swh:1:rev:0000000000000000000000000000000000000018",
        "swh:1:rev:0000000000000000000000000000000000000013",
        "swh:1:dir:0000000000000000000000000000000000000017",
        "swh:1:dir:0000000000000000000000000000000000000016",
        "swh:1:dir:0000000000000000000000000000000000000012",
        "swh:1:cnt:0000000000000000000000000000000000000015",
        "swh:1:cnt:0000000000000000000000000000000000000014",
        "swh:1:cnt:0000000000000000000000000000000000000011",
    }


def test_mark_removable_on_initial_origin_with_forked_origin_removed_and_oudated_graph(
    storage_with_forked_origin_removed,
    graph_client_with_both_origins,
    inventory_from_initial_origin,
):
    # Test the case of an outdated graph
    subgraph = mark_removable(
        storage_with_forked_origin_removed,
        graph_client_with_both_origins,
        inventory_from_initial_origin,
    )
    assert {str(swhid) for swhid in subgraph.removable_swhids()} == {
        "swh:1:ori:83404f995118bd25774f4ac14422a8f175e7a054",
        "swh:1:snp:0000000000000000000000000000000000000020",
        "swh:1:rel:0000000000000000000000000000000000000010",
        "swh:1:rev:0000000000000000000000000000000000000009",
        "swh:1:rev:0000000000000000000000000000000000000003",
        "swh:1:dir:0000000000000000000000000000000000000008",
        "swh:1:dir:0000000000000000000000000000000000000006",
        "swh:1:dir:0000000000000000000000000000000000000002",
        "swh:1:cnt:0000000000000000000000000000000000000007",
        "swh:1:cnt:0000000000000000000000000000000000000005",
        "swh:1:cnt:0000000000000000000000000000000000000004",
        "swh:1:cnt:0000000000000000000000000000000000000001",
    }


def test_mark_removable_on_stale_object_references_table(
    swh_storage,
    empty_graph_client,
    inventory_from_initial_origin,
):
    # Ensure we have the right revision pointing to the right directory
    directory = graph_dataset.DIRECTORIES[0]
    revision = graph_dataset.REVISIONS[0]
    assert directory.id == revision.directory

    swh_storage.revision_add([revision])
    swh_storage.directory_add([directory])
    result = swh_storage.flush()
    assert result == {"revision:add": 1, "directory:add": 1, "object_reference:add": 2}

    result = swh_storage.object_delete([revision.swhid().to_extended()])
    assert result["revision:delete"] == 1

    # Now the `object_references` table is outdated because it
    # contains a stale entry with “revision → directory”.
    # What if we try to remove the directory now?
    inventory_subgraph = InventorySubgraph()
    inventory_subgraph.add_swhid(str(directory.swhid()))
    subgraph = mark_removable(
        swh_storage,
        empty_graph_client,
        inventory_subgraph,
    )
    assert {str(swhid) for swhid in subgraph.removable_swhids()} == {
        str(directory.swhid())
    }


def test_mark_removable_with_known_missing(
    storage_with_forked_origin_removed,
    graph_client_with_only_initial_origin,
    inventory_from_initial_origin,
):
    known_missing = {
        ExtendedSWHID.from_string("swh:1:dir:0000000000000000000000000000000000000006"),
    }
    # Test the case of an outdated graph
    subgraph = mark_removable(
        storage_with_forked_origin_removed,
        graph_client_with_only_initial_origin,
        inventory_from_initial_origin,
        known_missing=known_missing,
    )
    assert {str(swhid) for swhid in subgraph.removable_swhids()} == {
        "swh:1:ori:83404f995118bd25774f4ac14422a8f175e7a054",
        "swh:1:snp:0000000000000000000000000000000000000020",
        "swh:1:rel:0000000000000000000000000000000000000010",
        "swh:1:rev:0000000000000000000000000000000000000009",
        "swh:1:rev:0000000000000000000000000000000000000003",
        "swh:1:dir:0000000000000000000000000000000000000008",
        "swh:1:dir:0000000000000000000000000000000000000002",
        "swh:1:cnt:0000000000000000000000000000000000000007",
        "swh:1:cnt:0000000000000000000000000000000000000005",
        "swh:1:cnt:0000000000000000000000000000000000000004",
        "swh:1:cnt:0000000000000000000000000000000000000001",
    }
    # Normally we would have removed everything, but objects
    # known missing are not considered removable, therefore
    # they won’t be in the recovery bundle, and thus are
    # referenced by the set of removable objects.
    assert set(subgraph.referenced_swhids()) == known_missing
