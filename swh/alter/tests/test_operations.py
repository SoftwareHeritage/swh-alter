# Copyright (C) 2023 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

from datetime import datetime, timedelta, timezone
import shutil
import subprocess

import pytest
import yaml

from swh.model.swhids import ExtendedObjectType, ExtendedSWHID
from swh.objstorage.interface import ObjStorageInterface
from swh.storage.interface import StorageInterface

from ..operations import Remover, RemoverError
from ..recovery_bundle import SecretSharing
from .test_inventory import (  # noqa
    directory_6_with_multiple_entries_pointing_to_the_same_content,
    snapshot_20_with_multiple_branches_pointing_to_the_same_head,
)
from .test_inventory import graph_client_with_only_initial_origin  # noqa: F401
from .test_inventory import sample_populated_storage  # noqa: F401
from .test_recovery_bundle import (
    TWO_GROUPS_REQUIRED_WITH_ONE_MINIMUM_SHARE_EACH_SECRET_SHARING_YAML,
)
from .test_removable import inventory_from_forked_origin  # noqa: F401
from .test_removable import storage_with_references_from_forked_origin  # noqa: F401


@pytest.fixture
def remover(
    storage_with_references_from_forked_origin,  # noqa: F811
    graph_client_with_only_initial_origin,  # noqa: F811
):
    return Remover(
        storage=storage_with_references_from_forked_origin,
        graph_client=graph_client_with_only_initial_origin,
    )


def test_remover_get_removable(remover):
    swhids = [
        ExtendedSWHID.from_string("swh:1:ori:83404f995118bd25774f4ac14422a8f175e7a054"),
        ExtendedSWHID.from_string("swh:1:ori:8f50d3f60eae370ddbf85c86219c55108a350165"),
    ]
    removable_swhids = remover.get_removable(swhids)
    assert len(removable_swhids) == 23


@pytest.mark.skipif(
    not shutil.which("gc"), reason="missing `gc` executable from graphviz"
)
def test_remover_output_inventory_subgraph(tmp_path, remover):
    swhids = [
        ExtendedSWHID.from_string("swh:1:ori:8f50d3f60eae370ddbf85c86219c55108a350165")
    ]
    dot_path = tmp_path / "subgraph.dot"
    _ = remover.get_removable(swhids, output_inventory_subgraph=dot_path.open("w"))
    completed_process = subprocess.run(
        ["gc", dot_path],
        check=True,
        capture_output=True,
    )
    assert b"      21      24 Inventory" in completed_process.stdout


@pytest.mark.skipif(
    not shutil.which("gc"), reason="missing `gc` executable from graphviz"
)
def test_remover_output_removable_subgraph(tmp_path, remover):
    swhids = [
        ExtendedSWHID.from_string("swh:1:ori:8f50d3f60eae370ddbf85c86219c55108a350165")
    ]
    dot_path = tmp_path / "subgraph.dot"
    _ = remover.get_removable(swhids, output_removable_subgraph=dot_path.open("w"))
    completed_process = subprocess.run(
        ["gc", dot_path],
        check=True,
        capture_output=True,
    )
    assert b"      21      24 Removable" in completed_process.stdout


@pytest.mark.skipif(
    not shutil.which("gc"), reason="missing `gc` executable from graphviz"
)
def test_remover_output_pruned_removable_subgraph(tmp_path, remover):
    swhids = [
        ExtendedSWHID.from_string("swh:1:ori:8f50d3f60eae370ddbf85c86219c55108a350165")
    ]
    dot_path = tmp_path / "subgraph.dot"
    _ = remover.get_removable(
        swhids, output_pruned_removable_subgraph=dot_path.open("w")
    )
    completed_process = subprocess.run(
        ["gc", dot_path],
        check=True,
        capture_output=True,
    )
    assert b"      11      10 Removable" in completed_process.stdout


@pytest.fixture
def secret_sharing_conf():
    return yaml.safe_load(
        TWO_GROUPS_REQUIRED_WITH_ONE_MINIMUM_SHARE_EACH_SECRET_SHARING_YAML
    )["secret_sharing"]


def test_remover_create_recovery_bundle(
    remover,
    secret_sharing_conf,
    tmp_path,
):
    swhids = [
        "swh:1:ori:8f50d3f60eae370ddbf85c86219c55108a350165",
        "swh:1:snp:0000000000000000000000000000000000000022",
        "swh:1:rel:0000000000000000000000000000000000000021",
        "swh:1:rev:0000000000000000000000000000000000000018",
        "swh:1:rev:0000000000000000000000000000000000000013",
        "swh:1:dir:0000000000000000000000000000000000000017",
        "swh:1:cnt:0000000000000000000000000000000000000015",
        "swh:1:cnt:0000000000000000000000000000000000000014",
    ]
    bundle_path = tmp_path / "test.swh-recovery-bundle"
    expire = datetime.now(timezone.utc) + timedelta(days=365)
    share_ids = {
        share_id
        for group in secret_sharing_conf["groups"].values()
        for share_id in group["recipient_keys"].keys()
    }
    remover.create_recovery_bundle(
        secret_sharing=SecretSharing.from_dict(secret_sharing_conf),
        removable_swhids=[ExtendedSWHID.from_string(swhid) for swhid in swhids],
        recovery_bundle_path=bundle_path,
        removal_identifier="test",
        reason="doing a test",
        expire=expire,
    )

    from ..recovery_bundle import RecoveryBundle

    bundle = RecoveryBundle(bundle_path)
    assert len(bundle.swhids) == len(swhids)
    assert bundle.removal_identifier == "test"
    assert bundle.reason == "doing a test"
    assert bundle.expire.isoformat(timespec="seconds") == expire.isoformat(
        timespec="seconds"
    )
    assert bundle.share_ids == share_ids


def test_remover_create_recovery_bundle_fails_with_expire_in_the_past(
    remover,
    secret_sharing_conf,
    tmp_path,
):
    swhids = [
        "swh:1:ori:8f50d3f60eae370ddbf85c86219c55108a350165",
    ]
    bundle_path = tmp_path / "test.swh-recovery-bundle"
    expire = datetime.fromisoformat("2001-01-01").astimezone()
    with pytest.raises(RemoverError, match="Unable to set expiration date"):
        remover.create_recovery_bundle(
            secret_sharing=SecretSharing.from_dict(secret_sharing_conf),
            removable_swhids=[ExtendedSWHID.from_string(swhid) for swhid in swhids],
            recovery_bundle_path=bundle_path,
            removal_identifier="test",
            reason="doing a test",
            expire=expire,
        )


def test_remover_remove(
    mocker,
    storage_with_references_from_forked_origin,  # noqa: F811
    graph_client_with_only_initial_origin,  # noqa: F811
):
    removal_storage_one = mocker.MagicMock()
    removal_storage_one.object_delete.return_value = {"origin:delete": 0}
    removal_storage_two = mocker.MagicMock()
    removal_storage_two.object_delete.return_value = {"origin:delete": 0}
    remover = Remover(
        storage_with_references_from_forked_origin,
        graph_client_with_only_initial_origin,
        removal_storages={"one": removal_storage_one, "two": removal_storage_two},
    )
    remover.swhids_to_remove = [
        ExtendedSWHID.from_string("swh:1:ori:8f50d3f60eae370ddbf85c86219c55108a350165"),
    ]
    remover.remove()
    for storage in (removal_storage_one, removal_storage_two):
        storage.object_delete.assert_called_once()
        args, _ = storage.object_delete.call_args
        assert set(args[0]) == set(remover.swhids_to_remove)


def test_remover_remove_from_objstorages(
    mocker,
    storage_with_references_from_forked_origin,  # noqa: F811
):
    from swh.objstorage.interface import objid_from_dict

    storage = storage_with_references_from_forked_origin
    objstorage1 = mocker.Mock(spec=ObjStorageInterface)
    objstorage2 = mocker.Mock(spec=ObjStorageInterface)
    graph_client = mocker.MagicMock()
    remover = Remover(
        storage,
        graph_client,
        removal_objstorages={"one": objstorage1, "two": objstorage2},
    )
    remover.swhids_to_remove = [
        ExtendedSWHID.from_string("swh:1:ori:8f50d3f60eae370ddbf85c86219c55108a350165"),
    ]
    contents = storage.content_get(
        [bytes.fromhex("0000000000000000000000000000000000000014")], algo="sha1_git"
    )
    remover.objids_to_remove = [
        objid_from_dict(content.to_dict()) for content in contents
    ]
    remover.remove()
    for objstorage in (objstorage1, objstorage2):
        objstorage.delete.assert_called_once()


def test_remover_have_new_references_outside_removed(
    mocker,
    storage_with_references_from_forked_origin,  # noqa:F811
    remover,
):
    storage = storage_with_references_from_forked_origin
    swhids = [
        "swh:1:ori:8f50d3f60eae370ddbf85c86219c55108a350165",
        "swh:1:snp:0000000000000000000000000000000000000022",
        "swh:1:rel:0000000000000000000000000000000000000021",
        "swh:1:rev:0000000000000000000000000000000000000018",
        "swh:1:rev:0000000000000000000000000000000000000013",
        "swh:1:dir:0000000000000000000000000000000000000017",
        "swh:1:cnt:0000000000000000000000000000000000000015",
        "swh:1:cnt:0000000000000000000000000000000000000014",
    ]
    mocker.patch.object(
        storage,
        "object_find_recent_references",
        wraps=lambda s, _: [
            ExtendedSWHID.from_string(
                "swh:1:rev:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            )
        ]
        if s.object_type == ExtendedObjectType.DIRECTORY
        else [],
    )
    result = remover.have_new_references(
        [ExtendedSWHID.from_string(swhid) for swhid in swhids]
    )
    assert result is True


def test_remover_have_new_references_inside_removed(
    mocker,
    storage_with_references_from_forked_origin,  # noqa:F811
    remover,
):
    storage = storage_with_references_from_forked_origin
    swhids = [
        "swh:1:ori:8f50d3f60eae370ddbf85c86219c55108a350165",
        "swh:1:snp:0000000000000000000000000000000000000022",
        "swh:1:rel:0000000000000000000000000000000000000021",
        "swh:1:rev:0000000000000000000000000000000000000018",
        "swh:1:rev:0000000000000000000000000000000000000013",
        "swh:1:dir:0000000000000000000000000000000000000017",
        "swh:1:cnt:0000000000000000000000000000000000000015",
        "swh:1:cnt:0000000000000000000000000000000000000014",
    ]
    mocker.patch.object(
        storage,
        "object_find_recent_references",
        wraps=lambda s, _: [
            ExtendedSWHID.from_string(
                "swh:1:rev:0000000000000000000000000000000000000013"
            )
        ]
        if s.object_type == ExtendedObjectType.DIRECTORY
        else [],
    )
    result = remover.have_new_references(
        [ExtendedSWHID.from_string(swhid) for swhid in swhids]
    )
    assert result is False


def test_remover_have_new_references_nothing_new(
    mocker,
    storage_with_references_from_forked_origin,  # noqa:F811
    remover,
):
    storage = storage_with_references_from_forked_origin
    swhids = [
        "swh:1:ori:8f50d3f60eae370ddbf85c86219c55108a350165",
        "swh:1:snp:0000000000000000000000000000000000000022",
        "swh:1:rel:0000000000000000000000000000000000000021",
        "swh:1:rev:0000000000000000000000000000000000000018",
        "swh:1:rev:0000000000000000000000000000000000000013",
        "swh:1:dir:0000000000000000000000000000000000000017",
        "swh:1:cnt:0000000000000000000000000000000000000015",
        "swh:1:cnt:0000000000000000000000000000000000000014",
    ]
    mocker.patch.object(storage, "object_find_recent_references", return_value=[])
    result = remover.have_new_references(
        [ExtendedSWHID.from_string(swhid) for swhid in swhids]
    )
    assert result is False


def test_remover_remove_fails_when_new_references_have_been_added(
    mocker,
    storage_with_references_from_forked_origin,  # noqa:F811
    remover,
):
    swhids = [
        "swh:1:cnt:0000000000000000000000000000000000000014",
    ]
    mocker.patch.object(remover, "have_new_references", return_value=True)
    remover.swhids_to_remove = [ExtendedSWHID.from_string(swhid) for swhid in swhids]
    with pytest.raises(RemoverError, match="New references"):
        remover.remove()


def test_remover_restore_recovery_bundle(
    mocker,
    storage_with_references_from_forked_origin,  # noqa: F811
    graph_client_with_only_initial_origin,  # noqa: F811
    secret_sharing_conf,
    tmp_path,
):
    bundle_path = tmp_path / "test.swh-recovery-bundle"
    mock = mocker.patch("swh.alter.operations.RecoveryBundle", autospec=True)
    instance = mock.return_value
    instance.restore.return_value = {"origin": 1}
    restoration_storage = mocker.Mock(spec=StorageInterface)

    remover = Remover(
        storage=storage_with_references_from_forked_origin,
        graph_client=graph_client_with_only_initial_origin,
        restoration_storage=restoration_storage,
    )

    swhids = [
        ExtendedSWHID.from_string("swh:1:ori:8f50d3f60eae370ddbf85c86219c55108a350165")
    ]
    remover.create_recovery_bundle(
        secret_sharing=SecretSharing.from_dict(secret_sharing_conf),
        removable_swhids=swhids,
        recovery_bundle_path=bundle_path,
        removal_identifier="test",
    )
    remover.restore_recovery_bundle()

    instance.restore.assert_called_once_with(restoration_storage)
