# Copyright (C) 2023-2024 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import datetime
import logging

import pytest

import swh.graph.example_dataset as graph_dataset
from swh.model.model import (
    Directory,
    DirectoryEntry,
    OriginVisit,
    OriginVisitStatus,
    Revision,
    RevisionType,
    Snapshot,
    SnapshotBranch,
    SnapshotTargetType,
    Timestamp,
    TimestampWithTimezone,
)
from swh.model.swhids import ExtendedSWHID

from ..inventory import (
    InventorySubgraph,
    Lister,
    StuckInventoryException,
    get_raw_extrinsic_metadata,
)
from .conftest import h

logger = logging.getLogger(__name__)


@pytest.fixture
def sample_data_inventory(sample_data_subgraph):
    return InventorySubgraph.copy(sample_data_subgraph)


def test_select_incomplete_returns_only_incomplete(sample_data_inventory):
    g = sample_data_inventory
    # Mark everything as complete
    g.vs["complete"] = True
    v1 = g.vs.find("swh:1:ori:8f50d3f60eae370ddbf85c86219c55108a350165")
    v2 = g.vs.find("swh:1:dir:0000000000000000000000000000000000000012")
    v1["complete"] = False
    v2["complete"] = False
    assert set(g.select_incomplete()) == {v1, v2}


def test_select_incomplete_returns_sorted_by_object_type(sample_data_inventory):
    g = sample_data_inventory
    # Mark everything as complete
    g.vs["complete"] = True
    v_ori = g.vs.find("swh:1:ori:8f50d3f60eae370ddbf85c86219c55108a350165")
    v_snp = g.vs.find("swh:1:snp:0000000000000000000000000000000000000020")
    v_rel = g.vs.find("swh:1:rel:0000000000000000000000000000000000000010")
    v_rev = g.vs.find("swh:1:rev:0000000000000000000000000000000000000009")
    v_dir = g.vs.find("swh:1:dir:0000000000000000000000000000000000000008")
    v_cnt = g.vs.find("swh:1:cnt:0000000000000000000000000000000000000007")
    for v in v_ori, v_snp, v_rel, v_rev, v_dir, v_cnt:
        v["complete"] = False
    assert g.select_incomplete() == [v_ori, v_snp, v_rel, v_rev, v_dir, v_cnt]


@pytest.fixture
def lister_with_populated_storage(
    sample_populated_storage, graph_client_with_both_origins
):
    return Lister(
        sample_populated_storage, graph_client_with_both_origins, InventorySubgraph()
    )


def assert_subgraph_is_full_from_forked_origin(subgraph):
    assert subgraph.to_list_dict(use_vids=False, sequence_constructor=set) == {
        "swh:1:ori:8f50d3f60eae370ddbf85c86219c55108a350165": {
            "swh:1:snp:0000000000000000000000000000000000000022"
        },
        "swh:1:snp:0000000000000000000000000000000000000022": {
            "swh:1:rel:0000000000000000000000000000000000000021",
            "swh:1:rel:0000000000000000000000000000000000000010",
            "swh:1:rev:0000000000000000000000000000000000000009",
        },
        "swh:1:rel:0000000000000000000000000000000000000021": {
            "swh:1:rev:0000000000000000000000000000000000000018"
        },
        "swh:1:rel:0000000000000000000000000000000000000010": {
            "swh:1:rev:0000000000000000000000000000000000000009"
        },
        "swh:1:rev:0000000000000000000000000000000000000018": {
            "swh:1:rev:0000000000000000000000000000000000000013",
            "swh:1:dir:0000000000000000000000000000000000000017",
        },
        "swh:1:rev:0000000000000000000000000000000000000013": {
            "swh:1:rev:0000000000000000000000000000000000000009",
            "swh:1:dir:0000000000000000000000000000000000000012",
        },
        "swh:1:rev:0000000000000000000000000000000000000009": {
            "swh:1:rev:0000000000000000000000000000000000000003",
            "swh:1:dir:0000000000000000000000000000000000000008",
        },
        "swh:1:rev:0000000000000000000000000000000000000003": {
            "swh:1:dir:0000000000000000000000000000000000000002"
        },
        "swh:1:dir:0000000000000000000000000000000000000017": {
            "swh:1:dir:0000000000000000000000000000000000000016",
            "swh:1:cnt:0000000000000000000000000000000000000014",
        },
        "swh:1:dir:0000000000000000000000000000000000000016": {
            "swh:1:cnt:0000000000000000000000000000000000000015"
        },
        "swh:1:dir:0000000000000000000000000000000000000012": {
            "swh:1:dir:0000000000000000000000000000000000000008",
            "swh:1:cnt:0000000000000000000000000000000000000011",
        },
        "swh:1:dir:0000000000000000000000000000000000000008": {
            "swh:1:dir:0000000000000000000000000000000000000006",
            "swh:1:cnt:0000000000000000000000000000000000000007",
            "swh:1:cnt:0000000000000000000000000000000000000001",
        },
        "swh:1:dir:0000000000000000000000000000000000000006": {
            "swh:1:cnt:0000000000000000000000000000000000000005",
            "swh:1:cnt:0000000000000000000000000000000000000004",
        },
        "swh:1:dir:0000000000000000000000000000000000000002": {
            "swh:1:cnt:0000000000000000000000000000000000000001"
        },
    }


# Adding candidates using graph
# =============================


# Testing from an origin should be enough as it should travel the whole graph
def test_add_edges_traversing_graph_from_origin(lister_with_populated_storage):
    origin_swhid = ExtendedSWHID.from_string(
        "swh:1:ori:8f50d3f60eae370ddbf85c86219c55108a350165"
    )
    lister_with_populated_storage.add_edges_traversing_graph(origin_swhid)
    subgraph = lister_with_populated_storage.subgraph
    assert_subgraph_is_full_from_forked_origin(subgraph)
    # But… the origin is still marked as incomplete as we want to see in swh.storage
    # if anything has been added since the swh.graph export
    assert len(subgraph.select_incomplete()) == 1


# Adding candidates using storage
# ===============================


def test_add_edges_using_storage_for_content(lister_with_populated_storage):
    content_swhid = ExtendedSWHID.from_string(
        "swh:1:cnt:0000000000000000000000000000000000000001"
    )
    lister_with_populated_storage.add_edges_using_storage(content_swhid)
    subgraph = lister_with_populated_storage.subgraph
    assert len(subgraph.vs) == 1
    assert (
        subgraph.vs.find("swh:1:cnt:0000000000000000000000000000000000000001")[
            "complete"
        ]
        is True
    )


def test_add_edges_using_storage_for_directory(lister_with_populated_storage):
    directory_swhid = ExtendedSWHID.from_string(
        "swh:1:dir:0000000000000000000000000000000000000008"
    )
    lister_with_populated_storage.add_edges_using_storage(directory_swhid)
    subgraph = lister_with_populated_storage.subgraph
    assert subgraph.to_list_dict(use_vids=False, sequence_constructor=set) == {
        "swh:1:dir:0000000000000000000000000000000000000008": {
            "swh:1:cnt:0000000000000000000000000000000000000001",
            "swh:1:cnt:0000000000000000000000000000000000000007",
            "swh:1:dir:0000000000000000000000000000000000000006",
        }
    }
    assert [v["name"] for v in subgraph.select_incomplete()] == [
        "swh:1:dir:0000000000000000000000000000000000000006"
    ]


def test_add_edges_using_storage_for_revision(lister_with_populated_storage):
    revision_swhid = ExtendedSWHID.from_string(
        "swh:1:rev:0000000000000000000000000000000000000013"
    )
    lister_with_populated_storage.add_edges_using_storage(revision_swhid)
    subgraph = lister_with_populated_storage.subgraph
    assert subgraph.to_list_dict(use_vids=False, sequence_constructor=set) == {
        "swh:1:rev:0000000000000000000000000000000000000013": {
            "swh:1:rev:0000000000000000000000000000000000000009",
            "swh:1:dir:0000000000000000000000000000000000000012",
        },
        "swh:1:rev:0000000000000000000000000000000000000009": {
            "swh:1:rev:0000000000000000000000000000000000000003",
            "swh:1:dir:0000000000000000000000000000000000000008",
        },
        "swh:1:rev:0000000000000000000000000000000000000003": {
            "swh:1:dir:0000000000000000000000000000000000000002"
        },
    }
    assert {v["name"] for v in subgraph.select_incomplete()} == {
        "swh:1:dir:0000000000000000000000000000000000000012",
        "swh:1:dir:0000000000000000000000000000000000000008",
        "swh:1:dir:0000000000000000000000000000000000000002",
    }


def test_add_edges_using_storage_for_revisions_with_common_parents(
    lister_with_populated_storage,
):
    newer_revision_swhid = ExtendedSWHID.from_string(
        "swh:1:rev:0000000000000000000000000000000000000018"
    )
    older_revision_swhid = ExtendedSWHID.from_string(
        "swh:1:rev:0000000000000000000000000000000000000009"
    )
    lister_with_populated_storage.add_edges_using_storage(newer_revision_swhid)
    lister_with_populated_storage.add_edges_using_storage(older_revision_swhid)
    subgraph = lister_with_populated_storage.subgraph
    assert {v["name"] for v in subgraph.select_incomplete()} == {
        "swh:1:dir:0000000000000000000000000000000000000017",
        "swh:1:dir:0000000000000000000000000000000000000012",
        "swh:1:dir:0000000000000000000000000000000000000008",
        "swh:1:dir:0000000000000000000000000000000000000002",
    }


@pytest.fixture
def revision_pointing_multiple_times_to_the_same_parent():
    return Revision(
        id=h(42),
        message=b"Weird revision",
        date=TimestampWithTimezone(
            timestamp=Timestamp(
                seconds=1111177770,
                microseconds=0,
            ),
            offset_bytes=b"+0000",
        ),
        committer=graph_dataset.PERSONS[0],
        author=graph_dataset.PERSONS[2],
        committer_date=TimestampWithTimezone(
            timestamp=Timestamp(
                seconds=1111177770,
                microseconds=0,
            ),
            offset_bytes=b"+0000",
        ),
        type=RevisionType.GIT,
        directory=h(2),
        synthetic=False,
        metadata=None,
        parents=(
            h(3),
            h(3),
        ),
    )


def test_add_edges_using_storage_for_revisions_pointing_multiple_times_to_the_same_parent(
    sample_populated_storage,
    graph_client_with_both_origins,
    revision_pointing_multiple_times_to_the_same_parent,
):
    storage = sample_populated_storage
    storage.revision_add([revision_pointing_multiple_times_to_the_same_parent])
    result = storage.flush()
    assert result == {"revision:add": 1, "object_reference:add": 2}
    lister = Lister(
        sample_populated_storage, graph_client_with_both_origins, InventorySubgraph()
    )
    revision_swhid = ExtendedSWHID.from_string(
        "swh:1:rev:0000000000000000000000000000000000000042"
    )
    lister.add_edges_using_storage(revision_swhid)
    subgraph = lister.subgraph
    assert subgraph.to_list_dict(use_vids=False, sequence_constructor=set) == {
        "swh:1:rev:0000000000000000000000000000000000000042": {
            "swh:1:rev:0000000000000000000000000000000000000003",
            "swh:1:dir:0000000000000000000000000000000000000002",
        },
        "swh:1:rev:0000000000000000000000000000000000000003": {
            "swh:1:dir:0000000000000000000000000000000000000002"
        },
    }


def test_add_edges_using_storage_for_release(lister_with_populated_storage):
    release_swhid = ExtendedSWHID.from_string(
        "swh:1:rel:0000000000000000000000000000000000000010"
    )
    lister_with_populated_storage.add_edges_using_storage(release_swhid)
    subgraph = lister_with_populated_storage.subgraph
    assert subgraph.to_list_dict(use_vids=False, sequence_constructor=set) == {
        "swh:1:rel:0000000000000000000000000000000000000010": {
            "swh:1:rev:0000000000000000000000000000000000000009"
        },
    }
    assert {v["name"] for v in subgraph.select_incomplete()} == {
        "swh:1:rev:0000000000000000000000000000000000000009"
    }


def test_add_edges_using_storage_for_snapshot(lister_with_populated_storage):
    snapshot_swhid = ExtendedSWHID.from_string(
        "swh:1:snp:0000000000000000000000000000000000000022"
    )
    lister_with_populated_storage.add_edges_using_storage(snapshot_swhid)
    subgraph = lister_with_populated_storage.subgraph
    assert subgraph.to_list_dict(use_vids=False, sequence_constructor=set) == {
        "swh:1:snp:0000000000000000000000000000000000000022": {
            "swh:1:rel:0000000000000000000000000000000000000021",
            "swh:1:rel:0000000000000000000000000000000000000010",
            "swh:1:rev:0000000000000000000000000000000000000009",
        },
    }
    assert {v["name"] for v in subgraph.select_incomplete()} == {
        "swh:1:rel:0000000000000000000000000000000000000021",
        "swh:1:rel:0000000000000000000000000000000000000010",
        "swh:1:rev:0000000000000000000000000000000000000009",
    }


def test_add_edges_using_storage_for_origin(lister_with_populated_storage):
    origin_swhid = ExtendedSWHID.from_string(
        "swh:1:ori:8f50d3f60eae370ddbf85c86219c55108a350165"
    )
    lister_with_populated_storage.add_edges_using_storage(origin_swhid)
    subgraph = lister_with_populated_storage.subgraph
    assert subgraph.to_list_dict(use_vids=False, sequence_constructor=set) == {
        "swh:1:ori:8f50d3f60eae370ddbf85c86219c55108a350165": {
            "swh:1:snp:0000000000000000000000000000000000000022"
        },
    }
    assert {v["name"] for v in subgraph.select_incomplete()} == {
        "swh:1:snp:0000000000000000000000000000000000000022"
    }


#
# Inventory candidates
# ====================


@pytest.fixture
def lister_with_full_graph(lister_with_populated_storage):
    return lister_with_populated_storage


@pytest.fixture
def lister_with_empty_graph(sample_populated_storage, empty_graph_client):
    return Lister(sample_populated_storage, empty_graph_client, InventorySubgraph())


@pytest.fixture
def lister_with_partial_graph(
    sample_populated_storage, graph_client_with_only_initial_origin
):
    return Lister(
        sample_populated_storage,
        graph_client_with_only_initial_origin,
        InventorySubgraph(),
    )


# Depending on our sources, we will need to iterate more or less
# to inventory all candidates. These tests ensure that we do not
# perform too many iterations: if the graph is full, we hardly
# need to query the storage. The less complete the graph is,
# the more iterations gets needed.
@pytest.mark.parametrize(
    "fixture, max_iterations",
    [
        ("lister_with_full_graph", 3),
        ("lister_with_partial_graph", 13),
        ("lister_with_empty_graph", 13),
    ],
)
def test_inventory_candidates(request, caplog, fixture, max_iterations):
    lister = request.getfixturevalue(fixture)
    with caplog.at_level(logging.DEBUG):
        lister.inventory_candidates(graph_dataset.FORKED_ORIGIN.swhid())
        log_lines = [
            record
            for record in caplog.records
            if record.funcName == "inventory_candidates"
        ]
        assert len(log_lines) <= max_iterations
        caplog.clear()
    assert_subgraph_is_full_from_forked_origin(lister.subgraph)


def test_inventory_candidates_stuck(
    caplog, sample_populated_storage, graph_client_with_both_origins
):
    subgraph = InventorySubgraph()
    # Add an incomplete node which does not exist neither in storage nor in graph
    inexistent_swhid = ExtendedSWHID.from_string(
        "swh:1:rev:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    )
    subgraph.add_swhid(inexistent_swhid, complete=False)
    lister = Lister(
        sample_populated_storage,
        graph_client_with_both_origins,
        subgraph,
    )
    with caplog.at_level(logging.DEBUG):
        with pytest.raises(StuckInventoryException) as exc_info:
            lister.inventory_candidates(graph_dataset.FORKED_ORIGIN.swhid())
    assert exc_info.value.swhids == [inexistent_swhid]
    assert (
        sum(
            "22 SWHIDS known,    1 need to be looked up" in msg
            for msg in caplog.messages
        )
        > 1
    )


def test_inventory_candidates_known_missing(
    sample_populated_storage, graph_client_with_both_origins
):
    subgraph = InventorySubgraph()
    # Add an incomplete node which does not exist neither in storage nor in graph
    inexistent_swhid = ExtendedSWHID.from_string(
        "swh:1:rev:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    )
    subgraph.add_swhid(inexistent_swhid, complete=False)
    lister = Lister(
        sample_populated_storage,
        graph_client_with_both_origins,
        subgraph,
        known_missing={inexistent_swhid},
    )
    lister.inventory_candidates(graph_dataset.FORKED_ORIGIN.swhid())
    assert len(lister.subgraph.vs.select(complete_eq=True)) == 21
    incomplete = lister.subgraph.select_incomplete()
    assert len(incomplete) == 1
    assert incomplete[0]["swhid"] == inexistent_swhid


#
# Submodules handling
# ===================


@pytest.fixture
def sample_populated_storage_using_submodule(
    sample_populated_storage, origin_with_submodule
):
    # dir 30 → rev 13
    directory_with_submodule = Directory(
        id=h(30),
        entries=(
            DirectoryEntry(
                name=b"submodule",
                perms=0o100644,
                type="rev",
                # We pick a revision from the forked origin so we can test
                # if this has influence on our ability to remove the forked origin
                target=h(13),
            ),
        ),
    )
    revision_date = TimestampWithTimezone(
        timestamp=Timestamp(
            seconds=1682496691,
            microseconds=0,
        ),
        offset_bytes=b"+0200",
    )
    # rev 31 → dir 30
    revision = Revision(
        id=h(31),
        message=b"Initial commit with submodule",
        date=revision_date,
        committer=graph_dataset.PERSONS[0],
        author=graph_dataset.PERSONS[0],
        committer_date=revision_date,
        type=RevisionType.GIT,
        directory=h(30),
        synthetic=False,
        metadata=None,
        parents=(),
    )
    # snp 32 → rev 31
    snapshot = Snapshot(
        id=h(32),
        branches={
            b"refs/heads/master": SnapshotBranch(
                target=h(31), target_type=SnapshotTargetType.REVISION
            ),
        },
    )
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    visit = OriginVisit(
        origin="https://example.com/swh/using-submodule",
        date=now,
        visit=1,
        type="git",
    )
    visit_status = OriginVisitStatus(
        origin="https://example.com/swh/using-submodule",
        date=now,
        visit=1,
        type="git",
        status="full",
        snapshot=h(32),
        metadata=None,
    )
    storage = sample_populated_storage
    storage.directory_add([directory_with_submodule])
    storage.revision_add([revision])
    storage.snapshot_add([snapshot])
    storage.origin_add([origin_with_submodule])
    storage.origin_visit_add([visit])
    storage.origin_visit_status_add([visit_status])
    result = storage.flush()
    assert result == {
        "directory:add": 1,
        "object_reference:add": 3,
        "revision:add": 1,
        "snapshot:add": 1,
    }
    return storage


@pytest.mark.parametrize(
    "graph_client_fixture, storage_fixture",
    [
        (
            "graph_client_with_both_origins",
            "sample_populated_storage_using_submodule",
        ),
        (
            "graph_client_with_submodule",
            "sample_populated_storage_using_submodule",
        ),
    ],
)
def test_inventory_with_submodule_stops_at_directory(
    request, graph_client_fixture, storage_fixture, origin_with_submodule
):
    graph_client = request.getfixturevalue(graph_client_fixture)
    storage = request.getfixturevalue(storage_fixture)
    lister = Lister(storage, graph_client, InventorySubgraph())
    lister.inventory_candidates(origin_with_submodule.swhid())
    assert {str(swhid) for swhid in lister.subgraph.swhids()} == {
        "swh:1:ori:73186715131824fa4381c6b5ca041c1c90207ef0",
        "swh:1:snp:0000000000000000000000000000000000000032",
        "swh:1:rev:0000000000000000000000000000000000000031",
        "swh:1:dir:0000000000000000000000000000000000000030",
    }


#
# RawExtrinsicMetadata objects
# ============================


def test_get_raw_extrinsic_metadata(sample_populated_storage):
    target_swhids = [
        ExtendedSWHID.from_string(str)
        for str in [
            "swh:1:ori:83404f995118bd25774f4ac14422a8f175e7a054",
            "swh:1:snp:0000000000000000000000000000000000000020",
            "swh:1:rel:0000000000000000000000000000000000000010",
            "swh:1:rev:0000000000000000000000000000000000000003",
            "swh:1:dir:0000000000000000000000000000000000000002",
            "swh:1:cnt:0000000000000000000000000000000000000001",
        ]
    ]
    assert list(
        get_raw_extrinsic_metadata(sample_populated_storage, target_swhids)
    ) == [
        ExtendedSWHID.from_string(str)
        for str in [
            "swh:1:emd:ba1e287385aac8d76caaf9956819a5d68bfe2083",
            "swh:1:emd:bfe476f7cffb00a5be2b12cfb364e207e4be0da2",
            "swh:1:emd:1ecd328c7597043895621da4d5351c59f1de663c",
            "swh:1:emd:bcfe01c5e96a675b500d32b15b4ea36bd5a46cdb",
            "swh:1:emd:1dd61e73df5a9c9cd422413462f0b623582f23a3",
            "swh:1:emd:f584cf10d8e222ccd1301e70d531d894fd3c3263",
            "swh:1:emd:482495bf2a894472462be6b1519bf43509bc2afe",
            "swh:1:emd:68d8ee6f7c1e6a07f72895d4460917c183fca21c",
            "swh:1:emd:d54fab7faa95094689f605314763170cf5fa2aa7",
            "swh:1:emd:a777e9317d1241a026f481b662f2b51a37297a32",
        ]
    ]
