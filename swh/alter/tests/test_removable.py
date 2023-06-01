# Copyright (C) 2023 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

from collections import defaultdict
from typing import List

import pytest

from swh.graph.example_dataset import FORKED_ORIGIN, INITIAL_ORIGIN
from swh.model.swhids import ExtendedSWHID

from ..inventory import InventorySubgraph
from ..removable import mark_removable
from .test_inventory import (  # noqa: F401
    directory_6_with_multiple_entries_pointing_to_the_same_content,
    snapshot_20_with_multiple_branches_pointing_to_the_same_head,
)
from .test_inventory import graph_client_with_both_origins  # noqa: F401
from .test_inventory import graph_client_with_only_initial_origin  # noqa: F401
from .test_inventory import graph_client_with_submodule  # noqa: F401
from .test_inventory import origin_with_submodule  # noqa: F401
from .test_inventory import sample_populated_storage  # noqa: F401
from .test_subgraph import write_dot_if_requested


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
def inventory_from_forked_origin():
    g = InventorySubgraph()
    v_ori = g.add_swhid(FORKED_ORIGIN.swhid())
    v_snp = g.add_swhid("swh:1:snp:0000000000000000000000000000000000000022")
    v_rel_21 = g.add_swhid("swh:1:rel:0000000000000000000000000000000000000021")
    v_rel_10 = g.add_swhid("swh:1:rel:0000000000000000000000000000000000000010")
    v_rev_18 = g.add_swhid("swh:1:rev:0000000000000000000000000000000000000018")
    v_rev_13 = g.add_swhid("swh:1:rev:0000000000000000000000000000000000000013")
    v_rev_09 = g.add_swhid("swh:1:rev:0000000000000000000000000000000000000009")
    v_rev_03 = g.add_swhid("swh:1:rev:0000000000000000000000000000000000000003")
    v_dir_17 = g.add_swhid("swh:1:dir:0000000000000000000000000000000000000017")
    v_dir_16 = g.add_swhid("swh:1:dir:0000000000000000000000000000000000000016")
    v_dir_12 = g.add_swhid("swh:1:dir:0000000000000000000000000000000000000012")
    v_dir_08 = g.add_swhid("swh:1:dir:0000000000000000000000000000000000000008")
    v_dir_06 = g.add_swhid("swh:1:dir:0000000000000000000000000000000000000006")
    v_dir_02 = g.add_swhid("swh:1:dir:0000000000000000000000000000000000000002")
    v_cnt_15 = g.add_swhid("swh:1:cnt:0000000000000000000000000000000000000015")
    v_cnt_14 = g.add_swhid("swh:1:cnt:0000000000000000000000000000000000000014")
    v_cnt_11 = g.add_swhid("swh:1:cnt:0000000000000000000000000000000000000011")
    v_cnt_07 = g.add_swhid("swh:1:cnt:0000000000000000000000000000000000000007")
    v_cnt_05 = g.add_swhid("swh:1:cnt:0000000000000000000000000000000000000005")
    v_cnt_04 = g.add_swhid("swh:1:cnt:0000000000000000000000000000000000000004")
    v_cnt_01 = g.add_swhid("swh:1:cnt:0000000000000000000000000000000000000001")
    g.add_edge(v_ori, v_snp)
    g.add_edge(v_snp, v_rel_21)
    g.add_edge(v_snp, v_rel_10)
    g.add_edge(v_snp, v_rev_09)
    g.add_edge(v_rel_21, v_rev_18)
    g.add_edge(v_rev_18, v_rev_13)
    g.add_edge(v_rev_13, v_rev_09)
    g.add_edge(v_rev_09, v_rev_03)
    g.add_edge(v_rev_18, v_dir_17)
    g.add_edge(v_rev_13, v_dir_12)
    g.add_edge(v_rev_09, v_dir_08)
    g.add_edge(v_rev_03, v_dir_02)
    g.add_edge(v_dir_17, v_dir_16)
    g.add_edge(v_dir_12, v_dir_08)
    g.add_edge(v_dir_08, v_dir_06)
    g.add_edge(v_dir_17, v_cnt_14)
    g.add_edge(v_dir_16, v_cnt_15)
    g.add_edge(v_dir_12, v_cnt_11)
    g.add_edge(v_dir_08, v_cnt_07)
    g.add_edge(v_dir_08, v_cnt_01)
    g.add_edge(v_dir_06, v_cnt_05)
    g.add_edge(v_dir_06, v_cnt_04)
    g.add_edge(v_dir_02, v_cnt_01)
    write_dot_if_requested(g, "inventory_from_forked_origin.dot")
    return g


@pytest.fixture
def storage_with_no_new_references_since_export(
    mocker, sample_populated_storage  # noqa: F811
):
    # Recent API, see:
    # https://gitlab.softwareheritage.org/swh/devel/swh-storage/-/merge_requests/1042
    mocker.patch.object(
        sample_populated_storage,
        "object_find_recent_references",
        create=True,
        return_value=[],
    )
    return sample_populated_storage


@pytest.fixture
def storage_with_references_from_forked_origin(
    mocker, sample_populated_storage, inventory_from_forked_origin  # noqa: F811
):
    references = defaultdict(list)
    for e in inventory_from_forked_origin.es:
        references[inventory_from_forked_origin.vs["swhid"][e.target]].append(
            inventory_from_forked_origin.vs["swhid"][e.source]
        )

    def find_recent_references(
        target: ExtendedSWHID, limit: int
    ) -> List[ExtendedSWHID]:
        return references[target]

    # Recent API, see:
    # https://gitlab.softwareheritage.org/swh/devel/swh-storage/-/merge_requests/1042
    mocker.patch.object(
        sample_populated_storage,
        "object_find_recent_references",
        create=True,
        side_effect=find_recent_references,
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
            "storage_with_references_from_forked_origin",
        ),
        (
            "graph_client_with_both_origins",
            "storage_with_references_from_forked_origin",
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
            "storage_with_references_from_forked_origin",
        ),
        (
            "graph_client_with_both_origins",
            "storage_with_references_from_forked_origin",
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
