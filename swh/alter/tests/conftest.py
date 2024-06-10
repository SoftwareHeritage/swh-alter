# Copyright (C) 2024 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

from collections import defaultdict
import datetime
import os
from typing import Iterator, List

import pytest

import swh.graph.example_dataset as graph_dataset
from swh.model.model import (
    Content,
    Directory,
    DirectoryEntry,
    ExtID,
    MetadataAuthority,
    MetadataAuthorityType,
    MetadataFetcher,
    Origin,
    RawExtrinsicMetadata,
    Snapshot,
    SnapshotBranch,
    SnapshotTargetType,
)
from swh.model.swhids import CoreSWHID, ExtendedObjectType, ExtendedSWHID
from swh.model.swhids import ObjectType as CoreSWHIDObjectType

from ..inventory import InventorySubgraph
from ..recovery_bundle import AgeSecretKey, Manifest, RecoveryBundle
from ..subgraph import Subgraph

#
# Test objects
# ============


def h(id: int, width=40) -> bytes:
    return bytes.fromhex(f"{id:0{width}}")


@pytest.fixture
def snapshot_20_with_multiple_branches_pointing_to_the_same_head():
    # No snapshot in the example dataset has multiple branches
    # or tags pointing to the same head. It’s pretty common in
    # the real world though, so let’s have a test with that.
    return Snapshot(
        id=h(20),
        branches={
            b"refs/heads/master": SnapshotBranch(
                target=h(9), target_type=SnapshotTargetType.REVISION
            ),
            b"refs/heads/dev": SnapshotBranch(
                target=h(9), target_type=SnapshotTargetType.REVISION
            ),
            b"refs/tags/v1.0": SnapshotBranch(
                target=h(10), target_type=SnapshotTargetType.RELEASE
            ),
        },
    )


@pytest.fixture
def directory_6_with_multiple_entries_pointing_to_the_same_content():
    # No directories in the example dataset has multiple entries
    # pointing to the same content. It can happen in the real world,
    # so let’s test that situation.
    return Directory(
        id=h(6),
        entries=(
            DirectoryEntry(
                name=b"README.md",
                perms=0o100644,
                type="file",
                target=h(4),
            ),
            DirectoryEntry(
                name=b"parser.c",
                perms=0o100644,
                type="file",
                target=h(5),
            ),
            DirectoryEntry(
                name=b"parser_backup.c",
                perms=0o100644,
                type="file",
                target=h(5),
            ),
        ),
    )


@pytest.fixture
def sample_extids():
    extid_snp = ExtID(
        target=CoreSWHID(object_type=CoreSWHIDObjectType.SNAPSHOT, object_id=h(20)),
        extid_type="snapshot",
        extid=h(20),
    )
    extid_rel1 = ExtID(
        target=CoreSWHID(object_type=CoreSWHIDObjectType.RELEASE, object_id=h(10)),
        extid_type="git",
        extid=h(10),
    )
    extid_rel2 = ExtID(
        target=CoreSWHID(object_type=CoreSWHIDObjectType.RELEASE, object_id=h(10)),
        extid_type="drink_some",
        extid=h(0xC0FFEE),
    )
    extid_rev = ExtID(
        target=CoreSWHID(object_type=CoreSWHIDObjectType.REVISION, object_id=h(3)),
        extid_type="revision",
        extid=h(3),
    )
    extid_dir = ExtID(
        target=CoreSWHID(object_type=CoreSWHIDObjectType.DIRECTORY, object_id=h(2)),
        extid_type="directory",
        extid=h(2),
    )
    extid_cnt = ExtID(
        target=CoreSWHID(object_type=CoreSWHIDObjectType.CONTENT, object_id=h(1)),
        extid_type="all_cats_are_beautiful",
        extid=h(0xACAB),
    )
    extid_skipped_content = ExtID(
        target=CoreSWHID(object_type=CoreSWHIDObjectType.CONTENT, object_id=h(15)),
        extid_type="skipped_content",
        extid=h(15),
    )
    return [
        extid_snp,
        extid_rel1,
        extid_rel2,
        extid_rev,
        extid_dir,
        extid_cnt,
        extid_skipped_content,
    ]


@pytest.fixture
def sample_metadata_authority_registry():
    return MetadataAuthority(
        type=MetadataAuthorityType.REGISTRY,
        url="https://wikidata.example.org/",
    )


@pytest.fixture
def sample_metadata_authority_deposit():
    return MetadataAuthority(
        type=MetadataAuthorityType.DEPOSIT_CLIENT,
        url="http://hal.inria.example.com/",
    )


@pytest.fixture
def sample_metadata_fetcher():
    return MetadataFetcher(
        name="swh-example",
        version="0.0.1",
    )


@pytest.fixture
def sample_raw_extrinsic_metadata_objects(
    sample_metadata_authority_registry,
    sample_metadata_authority_deposit,
    sample_metadata_fetcher,
):
    emd_ori1 = RawExtrinsicMetadata(
        target=graph_dataset.INITIAL_ORIGIN.swhid(),
        discovery_date=datetime.datetime(
            2015, 1, 1, 21, 0, 0, tzinfo=datetime.timezone.utc
        ),
        authority=sample_metadata_authority_registry,
        fetcher=sample_metadata_fetcher,
        format="json",
        metadata=b'{"position": "initial"}',
    )
    emd_ori2 = RawExtrinsicMetadata(
        target=graph_dataset.INITIAL_ORIGIN.swhid(),
        discovery_date=datetime.datetime(
            2016, 1, 1, 21, 0, 0, tzinfo=datetime.timezone.utc
        ),
        authority=sample_metadata_authority_registry,
        fetcher=sample_metadata_fetcher,
        format="json",
        metadata=b'{"history": "updated"}',
    )
    emd_ori3 = RawExtrinsicMetadata(
        target=graph_dataset.INITIAL_ORIGIN.swhid(),
        discovery_date=datetime.datetime(
            2016, 1, 1, 21, 0, 0, tzinfo=datetime.timezone.utc
        ),
        authority=sample_metadata_authority_deposit,
        fetcher=sample_metadata_fetcher,
        format="json",
        metadata=b'{"some": "thing"}',
    )
    emd_snp = RawExtrinsicMetadata(
        target=ExtendedSWHID(object_type=ExtendedObjectType.SNAPSHOT, object_id=h(20)),
        discovery_date=datetime.datetime(
            2015, 1, 1, 21, 0, 0, tzinfo=datetime.timezone.utc
        ),
        authority=sample_metadata_authority_registry,
        fetcher=sample_metadata_fetcher,
        format="json",
        metadata=b'{"violet": "blue"}',
    )
    emd_rel = RawExtrinsicMetadata(
        target=ExtendedSWHID(object_type=ExtendedObjectType.RELEASE, object_id=h(10)),
        discovery_date=datetime.datetime(
            2015, 1, 1, 21, 0, 0, tzinfo=datetime.timezone.utc
        ),
        authority=sample_metadata_authority_registry,
        fetcher=sample_metadata_fetcher,
        format="json",
        metadata=b'{"roses": "red"}',
    )
    emd_rev = RawExtrinsicMetadata(
        target=ExtendedSWHID(object_type=ExtendedObjectType.REVISION, object_id=h(3)),
        discovery_date=datetime.datetime(
            2015, 1, 1, 21, 0, 0, tzinfo=datetime.timezone.utc
        ),
        authority=sample_metadata_authority_registry,
        fetcher=sample_metadata_fetcher,
        format="json",
        metadata=b'{"love": "you"}',
    )
    emd_dir = RawExtrinsicMetadata(
        target=ExtendedSWHID(object_type=ExtendedObjectType.DIRECTORY, object_id=h(2)),
        discovery_date=datetime.datetime(
            2015, 1, 1, 21, 0, 0, tzinfo=datetime.timezone.utc
        ),
        authority=sample_metadata_authority_registry,
        fetcher=sample_metadata_fetcher,
        format="json",
        metadata=b'{"cheesy": "true"}',
    )
    emd_cnt = RawExtrinsicMetadata(
        target=ExtendedSWHID(object_type=ExtendedObjectType.CONTENT, object_id=h(1)),
        discovery_date=datetime.datetime(
            2015, 1, 1, 21, 0, 0, tzinfo=datetime.timezone.utc
        ),
        authority=sample_metadata_authority_registry,
        fetcher=sample_metadata_fetcher,
        format="json",
        metadata=b'{"address": "gemini"}',
        origin=graph_dataset.INITIAL_ORIGIN.url,
        visit=1,
        snapshot=CoreSWHID(object_type=CoreSWHIDObjectType.SNAPSHOT, object_id=h(20)),
        release=CoreSWHID(object_type=CoreSWHIDObjectType.RELEASE, object_id=h(10)),
        revision=CoreSWHID(object_type=CoreSWHIDObjectType.REVISION, object_id=h(3)),
        directory=CoreSWHID(object_type=CoreSWHIDObjectType.DIRECTORY, object_id=h(2)),
        path=b"/over/the/rainbow",
    )
    emd_emd = RawExtrinsicMetadata(
        target=emd_cnt.swhid(),
        discovery_date=datetime.datetime(
            2015, 1, 1, 21, 0, 0, tzinfo=datetime.timezone.utc
        ),
        authority=sample_metadata_authority_deposit,
        fetcher=sample_metadata_fetcher,
        format="json",
        metadata=b'{"meta": "meta"}',
    )
    emd_emd_emd = RawExtrinsicMetadata(
        target=emd_emd.swhid(),
        discovery_date=datetime.datetime(
            2015, 1, 1, 21, 0, 0, tzinfo=datetime.timezone.utc
        ),
        authority=sample_metadata_authority_deposit,
        fetcher=sample_metadata_fetcher,
        format="json",
        metadata=b'{"meta": "meta-meta"}',
    )
    return [
        emd_ori1,
        emd_ori2,
        emd_ori3,
        emd_snp,
        emd_rel,
        emd_rev,
        emd_dir,
        emd_cnt,
        emd_emd,
        emd_emd_emd,
    ]


def fix_contents(contents: Iterator[Content]) -> Iterator[Content]:
    """Recreate more complete Content objects using the same SWHIDs as the ones given.

    The content objects provided by :py:module:`swh.graph.example_dataset` are not
    complete enough to be inserted in a ``swh.storage``, so we make up what’s missing
    here."""
    for content in contents:
        swhid_value = int.from_bytes(content.swhid().object_id, "big")
        yield Content.from_dict(
            {
                "sha1": bytes.fromhex(f"{swhid_value:040x}"),
                "sha1_git": bytes.fromhex(f"{swhid_value:040x}"),
                "sha256": bytes.fromhex(f"{swhid_value:064x}"),
                "blake2s256": bytes.fromhex(f"{swhid_value:064x}"),
                "data": b"",
                "length": 0,
                "ctime": datetime.datetime.now(tz=datetime.timezone.utc),
            }
        )


@pytest.fixture
def origin_with_submodule():
    # swh:1:ori:73186715131824fa4381c6b5ca041c1c90207ef0
    return Origin(url="https://example.com/swh/using-submodule")


#
# Graph clients
# =============


@pytest.fixture
def empty_graph_client(naive_graph_client):
    from swh.graph.http_naive_client import NaiveClient

    return NaiveClient(nodes=[], edges=[])


@pytest.fixture
def graph_client_with_only_initial_origin(naive_graph_client):
    from swh.graph.http_naive_client import NaiveClient

    initial_origin = str(graph_dataset.INITIAL_ORIGIN.swhid())
    return NaiveClient(
        nodes=list(naive_graph_client.visit_nodes(initial_origin)),
        edges=list(naive_graph_client.visit_edges(initial_origin)),
    )


@pytest.fixture
def graph_client_with_both_origins(naive_graph_client):
    from swh.graph.http_naive_client import NaiveClient

    # swh.graph.example_dataset contains a dangling release which would
    # prevent us from removing any revisions, directories or contents in our tests.
    # We skip it by reconstructing a graph from both origins
    initial_origin = str(graph_dataset.INITIAL_ORIGIN.swhid())
    forked_origin = str(graph_dataset.FORKED_ORIGIN.swhid())
    nodes = set(naive_graph_client.visit_nodes(initial_origin)) | set(
        naive_graph_client.visit_nodes(forked_origin)
    )
    edges = set(naive_graph_client.visit_edges(initial_origin)) | set(
        naive_graph_client.visit_edges(forked_origin)
    )
    return NaiveClient(nodes=nodes, edges=edges)


@pytest.fixture
def graph_client_with_submodule(naive_graph_client, origin_with_submodule):
    from swh.graph.http_naive_client import NaiveClient

    initial_origin = str(graph_dataset.INITIAL_ORIGIN.swhid())
    forked_origin = str(graph_dataset.FORKED_ORIGIN.swhid())

    extra_nodes = {
        origin_with_submodule,
        "swh:1:snp:0000000000000000000000000000000000000032",
        "swh:1:rev:0000000000000000000000000000000000000031",
        "swh:1:rev:0000000000000000000000000000000000000013",
        "swh:1:dir:0000000000000000000000000000000000000030",
    }
    extra_edges = {
        (origin_with_submodule, "swh:1:snp:0000000000000000000000000000000000000032"),
        (
            "swh:1:snp:0000000000000000000000000000000000000032",
            "swh:1:rev:0000000000000000000000000000000000000031",
        ),
        (
            "swh:1:rev:0000000000000000000000000000000000000031",
            "swh:1:dir:0000000000000000000000000000000000000030",
        ),
        (
            "swh:1:dir:0000000000000000000000000000000000000030",
            "swh:1:rev:0000000000000000000000000000000000000013",
        ),
    }
    nodes = (
        set(naive_graph_client.visit_nodes(initial_origin))
        | set(naive_graph_client.visit_nodes(forked_origin))
        | extra_nodes
    )
    edges = (
        set(naive_graph_client.visit_edges(initial_origin))
        | set(naive_graph_client.visit_edges(forked_origin))
        | extra_edges
    )
    return NaiveClient(nodes=nodes, edges=edges)


#
# Storages
# ========


@pytest.fixture
def sample_populated_storage(
    swh_storage,
    snapshot_20_with_multiple_branches_pointing_to_the_same_head,
    directory_6_with_multiple_entries_pointing_to_the_same_content,
    sample_extids,
    sample_metadata_authority_registry,
    sample_metadata_authority_deposit,
    sample_metadata_fetcher,
    sample_raw_extrinsic_metadata_objects,
):
    result = swh_storage.content_add(fix_contents(graph_dataset.CONTENTS))
    assert result.get("content:add") == 6
    result = swh_storage.skipped_content_add(graph_dataset.SKIPPED_CONTENTS)
    assert result == {"skipped_content:add": 1}
    directories = list(graph_dataset.DIRECTORIES)
    directories[1] = directory_6_with_multiple_entries_pointing_to_the_same_content
    result = swh_storage.directory_add(directories)
    assert result == {"directory:add": 6}
    result = swh_storage.revision_add(graph_dataset.REVISIONS)
    assert result == {"revision:add": 4}
    # swh.graph.example_dataset contains a dangling release which would
    # prevent us from removing any revisions, directories or contents in our tests.
    # We need to skip it.
    result = swh_storage.release_add(
        [
            rel
            for rel in graph_dataset.RELEASES
            if str(rel.swhid()) != "swh:1:rel:0000000000000000000000000000000000000019"
        ]
    )
    assert result == {"release:add": 2}
    snapshot_22 = graph_dataset.SNAPSHOTS[1]
    result = swh_storage.snapshot_add(
        [snapshot_20_with_multiple_branches_pointing_to_the_same_head, snapshot_22]
    )
    assert result == {"snapshot:add": 2}
    result = swh_storage.origin_add(graph_dataset.ORIGINS)
    assert result == {"origin:add": 2}
    swh_storage.origin_visit_add(graph_dataset.ORIGIN_VISITS)
    swh_storage.origin_visit_status_add(graph_dataset.ORIGIN_VISIT_STATUSES)
    result = swh_storage.extid_add(sample_extids)
    assert result == {"extid:add": 7}
    result = swh_storage.metadata_authority_add(
        [sample_metadata_authority_registry, sample_metadata_authority_deposit]
    )
    assert result == {"metadata_authority:add": 2}
    result = swh_storage.metadata_fetcher_add([sample_metadata_fetcher])
    assert result == {"metadata_fetcher:add": 1}
    result = swh_storage.raw_extrinsic_metadata_add(
        sample_raw_extrinsic_metadata_objects
    )
    assert result == {
        "ori_metadata:add": 3,
        "snp_metadata:add": 1,
        "rev_metadata:add": 1,
        "rel_metadata:add": 1,
        "dir_metadata:add": 1,
        "cnt_metadata:add": 1,
        "emd_metadata:add": 2,
    }
    return swh_storage


@pytest.fixture
def storage_with_forked_origin_removed(sample_populated_storage):
    removed_swhids = [
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
    ]
    result = sample_populated_storage.object_delete(
        [ExtendedSWHID.from_string(swhid) for swhid in removed_swhids]
    )
    assert result == {
        "content:delete": 2,
        "content:delete:bytes": 0,
        "directory:delete": 3,
        "origin:delete": 1,
        "origin_visit:delete": 1,
        "origin_visit_status:delete": 1,
        "release:delete": 1,
        "revision:delete": 2,
        "skipped_content:delete": 1,
        "snapshot:delete": 1,
    }
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


#
# Subgraphs
# =========


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


#
# InventorySubgraphs
# ==================


@pytest.fixture
def inventory_from_forked_origin():
    g = InventorySubgraph()
    v_ori = g.add_swhid(graph_dataset.FORKED_ORIGIN.swhid())
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


#
# Recovery bundles
# ================


OBJECT_PUBLIC_KEY = "age1a4uwpku4xzlnkh78ma3urlulhhhz0xlsv6crthjvhrjysvskp9nsz77qts"
OBJECT_SECRET_KEY = (
    "AGE-SECRET-KEY-1EZMJLS2MMEN4D6CCR6TQ66RD4MPT32ZN8EAU44PS3EDNUAKQWE0SM92NN4"
)

ALI_PUBLIC_KEY = "age123hpq9m25xsmx7caqvyv8k3fxaqastc3evyq9q7myur7l9ukj4dsnp7a5v"
ALI_SECRET_KEY = (
    "AGE-SECRET-KEY-1VREXCYE5WNMUD0WSCF7F6CH3FGQ9P6PGD25QHY7QX8PGDN87P37QQD3L2G"
)
BOB_PUBLIC_KEY = "age1mrhte5tlpzpz57gg85nzcefqc5pm5usmakqpuurxux7ry2rmhdgs7r9u68"
BOB_SECRET_KEY = (
    "AGE-SECRET-KEY-1UPJU3AF4M0NPLSLGVDWJU38F3MDE3JJM48E8NST8V3YKU077HEVSQVPZC2"
)
CAMILLE_PUBLIC_KEY = "age1ahuqxgjmvfm65shmwqa7xa703vvcla528swga3zempnxslj3pczqtx6wr8"
CAMILLE_SECRET_KEY = (
    "AGE-SECRET-KEY-1NPLST9VXL6E9DEHCVVPUTGH60ZRJFLPZ5HDM93MJW993CGFQ49PQU90RVL"
)
DLIQUE_PUBLIC_KEY = "age1qwu50kncctmpky7gg5s0v4mt4fzc4wjwj6mfjzhtk3wn6pspkyksmsmhze"
DLIQUE_SECRET_KEY = (
    "AGE-SECRET-KEY-1NPT3PFA7N03DFQY9GN764T4TJCZSLP36YV4S98FLYN0YGX2539GSSFUT4F"
)
ESSUN_PUBLIC_KEY = "age1uakt638m65nt56q9qjecwp60gnv6qwqkez43re06awqzf8hqh3pqnsppaw"
ESSUN_SECRET_KEY = (
    "AGE-SECRET-KEY-10ZZWX7FNCUJR7HRACEGUCVA4V0PYGLQ7NJDYPRH96YNC3AJLM37QQNWX3K"
)


TWO_GROUPS_REQUIRED_WITH_ONE_MINIMUM_SHARE_EACH_SECRET_SHARING_YAML = f"""\
secret_sharing:
  minimum_required_groups: 2
  groups:
    legal:
      minimum_required_shares: 1
      recipient_keys:
        "Ali": {ALI_PUBLIC_KEY}
        "Bob": {BOB_PUBLIC_KEY}
    sysadmins:
      minimum_required_shares: 1
      recipient_keys:
        "Camille": {CAMILLE_PUBLIC_KEY}
        "Dlique": {DLIQUE_PUBLIC_KEY}
"""


@pytest.fixture(params=["version-1", "version-2"])
def sample_recovery_bundle_path(request):
    return os.path.join(
        os.path.dirname(__file__),
        "fixtures",
        f"sample-{request.param}.swh-recovery-bundle",
    )


def object_decryption_key_provider_for_sample(manifest: Manifest) -> AgeSecretKey:
    return OBJECT_SECRET_KEY


@pytest.fixture
def sample_recovery_bundle(sample_recovery_bundle_path):
    return RecoveryBundle(
        sample_recovery_bundle_path, object_decryption_key_provider_for_sample
    )