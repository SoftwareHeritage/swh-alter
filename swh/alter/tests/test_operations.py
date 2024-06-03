# Copyright (C) 2023 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

from datetime import datetime, timedelta, timezone
import logging
import shutil
import subprocess
from typing import Any, List, Set
from unittest.mock import call

import pytest
import yaml

from swh.model.model import BaseModel
from swh.model.swhids import CoreSWHID, ExtendedObjectType, ExtendedSWHID
from swh.objstorage.interface import ObjStorageInterface
from swh.search.interface import SearchInterface
from swh.storage.interface import StorageInterface

from ..operations import Remover, RemoverError
from ..recovery_bundle import SecretSharing
from .test_inventory import (  # noqa
    directory_6_with_multiple_entries_pointing_to_the_same_content,
    snapshot_20_with_multiple_branches_pointing_to_the_same_head,
)
from .test_inventory import graph_client_with_only_initial_origin  # noqa: F401
from .test_inventory import sample_extids  # noqa: F401
from .test_inventory import sample_metadata_authority_deposit  # noqa: F401
from .test_inventory import sample_metadata_authority_registry  # noqa: F401
from .test_inventory import sample_metadata_fetcher  # noqa: F401
from .test_inventory import sample_populated_storage  # noqa: F401
from .test_inventory import sample_raw_extrinsic_metadata_objects  # noqa: F401
from .test_recovery_bundle import (
    OBJECT_SECRET_KEY,
    TWO_GROUPS_REQUIRED_WITH_ONE_MINIMUM_SHARE_EACH_SECRET_SHARING_YAML,
)
from .test_recovery_bundle import sample_recovery_bundle  # noqa: F401
from .test_recovery_bundle import sample_recovery_bundle_path  # noqa: F401
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
    assert len(removable_swhids) == 33


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
    removal_storage_one.extid_delete_for_target.return_value = {"extid:delete": 0}
    removal_storage_two = mocker.MagicMock()
    removal_storage_two.object_delete.return_value = {"origin:delete": 0}
    removal_storage_two.extid_delete_for_target.return_value = {"extid:delete": 0}
    remover = Remover(
        storage_with_references_from_forked_origin,
        graph_client_with_only_initial_origin,
        removal_storages={"one": removal_storage_one, "two": removal_storage_two},
    )
    core_swhids = """\
        swh:1:snp:0000000000000000000000000000000000000022
        swh:1:rev:0000000000000000000000000000000000000018
        swh:1:rel:0000000000000000000000000000000000000021
    """
    remover.swhids_to_remove = [
        ExtendedSWHID.from_string("swh:1:ori:8f50d3f60eae370ddbf85c86219c55108a350165")
    ] + [
        ExtendedSWHID.from_string(line.strip())
        for line in core_swhids.rstrip().splitlines()
    ]
    remover.remove()
    for storage in (removal_storage_one, removal_storage_two):
        storage.object_delete.assert_called_once()
        args, _ = storage.object_delete.call_args
        assert set(args[0]) == set(remover.swhids_to_remove)
        storage.extid_delete_for_target.assert_called_once()
        args, _ = storage.extid_delete_for_target.call_args
        assert set(args[0]) == {
            CoreSWHID.from_string(line.strip())
            for line in core_swhids.rstrip().splitlines()
        }


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


def test_remover_remove_from_searches(
    mocker,
    storage_with_references_from_forked_origin,  # noqa: F811
):
    storage = storage_with_references_from_forked_origin
    search1 = mocker.Mock(spec=SearchInterface)
    search2 = mocker.Mock(spec=SearchInterface)
    graph_client = mocker.MagicMock()
    remover = Remover(
        storage,
        graph_client,
        removal_searches={"one": search1, "two": search2},
    )
    remover.origin_urls_to_remove = [
        "https://example.com/swh/graph1",
        "https://example.com/swh/graph2",
    ]
    remover.remove()
    for search in (search1, search2):
        assert search.origin_delete.call_args_list == [
            call("https://example.com/swh/graph1"),
            call("https://example.com/swh/graph2"),
        ]
        search.flush.assert_called_once()


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
    caplog,
    mocker,
    storage_with_references_from_forked_origin,  # noqa: F811
    graph_client_with_only_initial_origin,  # noqa: F811
    secret_sharing_conf,
    tmp_path,
):
    from ..progressbar import no_progressbar

    bundle_path = tmp_path / "test.swh-recovery-bundle"
    mock = mocker.patch("swh.alter.operations.RecoveryBundle", autospec=True)
    instance = mock.return_value
    instance.restore.return_value = {
        "origin:add": 1,
        "origin_visit:add": 1,
        "origin_visit_status:add": 1,
    }
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

    with caplog.at_level(logging.INFO):
        remover.restore_recovery_bundle()
    assert "3 objects restored" in caplog.text
    assert "Something might be wrong" not in caplog.text

    instance.restore.assert_called_once_with(restoration_storage, no_progressbar)


def test_remover_restore_recovery_bundle_logs_insert_count_mismatch(
    caplog,
    mocker,
    storage_with_references_from_forked_origin,  # noqa: F811
    graph_client_with_only_initial_origin,  # noqa: F811
    tmp_path,
):
    mock = mocker.patch("swh.alter.operations.RecoveryBundle", autospec=True)
    instance = mock.return_value
    instance.restore.return_value = {"origin:add": 1}
    restoration_storage = mocker.Mock(spec=StorageInterface)

    remover = Remover(
        storage=storage_with_references_from_forked_origin,
        graph_client=graph_client_with_only_initial_origin,
        restoration_storage=restoration_storage,
    )
    # Force a path. It’ll use the mock anyway
    remover.recovery_bundle_path = tmp_path / "nonexistent.swh-recovery-bundle"

    with caplog.at_level(logging.DEBUG):
        remover.restore_recovery_bundle()

    # We force a mismatch situation. Make sure this one is unpopulated:
    assert remover.journal_objects_to_remove == {}

    assert "Something might be wrong!" in caplog.text


def test_remover_register_objects_from_bundle(
    request,
    mocker,
    remover,
    sample_recovery_bundle_path,  # noqa: F811
):
    obj_swhids: Set[str] = set()
    # We cannot use a Set as dict are not hashable
    obj_unique_keys: List[Any] = []

    def register_object(obj: BaseModel):
        if hasattr(obj, "swhid"):
            obj_swhids.add(str(obj.swhid()))
        obj_unique_keys.append(obj.unique_key())

    mocker.patch.object(remover, "register_object", side_effect=register_object)

    remover.register_objects_from_bundle(
        recovery_bundle_path=sample_recovery_bundle_path,
        object_secret_key=OBJECT_SECRET_KEY,
    )

    expected_swhids = {
        "swh:1:cnt:d81cc0710eb6cf9efd5b920a8453e1e07157b6cd",
        "swh:1:cnt:c932c7649c6dfa4b82327d121215116909eb3bea",
        "swh:1:cnt:33e45d56f88993aae6a0198013efa80716fd8920",
        "swh:1:dir:5256e856a0a0898966d6ba14feb4388b8b82d302",
        "swh:1:dir:4b825dc642cb6eb9a060e54bf8d69288fbee4904",
        "swh:1:dir:afa0105cfcaa14fdbacee344e96659170bb1bda5",
        "swh:1:rev:01a7114f36fddd5ef2511b2cadda237a68adbb12",
        "swh:1:rev:a646dd94c912829659b22a1e7e143d2fa5ebde1b",
        "swh:1:rel:f7f222093a18ec60d781070abec4a630c850b837",
        "swh:1:rel:db81a26783a3f4a9db07b4759ffc37621f159bb2",
        "swh:1:snp:9b922e6d8d5b803c1582aabe5525b7b91150788e",
        "swh:1:snp:db99fda25b43dc5cd90625ee4b0744751799c917",
        "swh:1:ori:33abd4b4c5db79c7387673f71302750fd73e0645",
        "swh:1:ori:9147ab9c9287940d4fdbe95d8780664d7ad2dfc0",
    }
    if "version-1" not in request.keywords:
        expected_swhids |= {
            "swh:1:emd:101d70c3574c1e4b730d7ba8e83a4bdadc8691cb",
            "swh:1:emd:43dad4d96edf2fb4f77f0dbf72113b8fe8b5b664",
            "swh:1:emd:9cafd9348f3a7729c2ef0b9b149ba421589427f0",
            "swh:1:emd:ef3b0865c7a05f79772a3189ddfc8515ec3e1844",
        }
    assert obj_swhids == expected_swhids
    expected_unique_keys = [
        bytes.fromhex("3e21cc4942a4234c9e5edd8a9cacd1670fe59f13"),
        bytes.fromhex("34973274ccef6ab4dfaaf86599792fa9c3fe4689"),
        {
            "sha1": bytes.fromhex("43e45d56f88993aae6a0198013efa80716fd8920"),
            "sha1_git": bytes.fromhex("33e45d56f88993aae6a0198013efa80716fd8920"),
            "sha256": bytes.fromhex(
                "7bbd052ab054ef222c1c87be60cd191addedd24cc882d1f5f7f7be61dc61bb3a"
            ),
            "blake2s256": bytes.fromhex(
                "ade18b1adecb33f891ca36664da676e12c772cc193778aac9a137b8dc5834b9b"
            ),
        },
        bytes.fromhex("4b825dc642cb6eb9a060e54bf8d69288fbee4904"),
        bytes.fromhex("5256e856a0a0898966d6ba14feb4388b8b82d302"),
        bytes.fromhex("afa0105cfcaa14fdbacee344e96659170bb1bda5"),
        bytes.fromhex("01a7114f36fddd5ef2511b2cadda237a68adbb12"),
        bytes.fromhex("a646dd94c912829659b22a1e7e143d2fa5ebde1b"),
        bytes.fromhex("db81a26783a3f4a9db07b4759ffc37621f159bb2"),
        bytes.fromhex("f7f222093a18ec60d781070abec4a630c850b837"),
        bytes.fromhex("9b922e6d8d5b803c1582aabe5525b7b91150788e"),
        bytes.fromhex("db99fda25b43dc5cd90625ee4b0744751799c917"),
    ]
    if "version-1" not in request.keywords:
        expected_unique_keys.extend(
            [
                # RawExtrinsicMetadata
                bytes.fromhex("101d70c3574c1e4b730d7ba8e83a4bdadc8691cb"),
                bytes.fromhex("ef3b0865c7a05f79772a3189ddfc8515ec3e1844"),
                bytes.fromhex("43dad4d96edf2fb4f77f0dbf72113b8fe8b5b664"),
                bytes.fromhex("9cafd9348f3a7729c2ef0b9b149ba421589427f0"),
                # ExtID
                bytes.fromhex("486e20ccedc221075b12abbb607a888875db41f6"),
                bytes.fromhex("fa730cf0bb415e1e921e430984bdcddd9c8eea4a"),
            ]
        )
    expected_unique_keys.extend(
        [
            {"url": "https://github.com/user1/repo1"},
            {
                "origin": "https://github.com/user1/repo1",
                "date": "2015-01-01 23:00:00+00:00",
            },
            {
                "origin": "https://github.com/user1/repo1",
                "date": "2017-01-01 23:00:00+00:00",
            },
            {
                "origin": "https://github.com/user1/repo1",
                "visit": "1",
                "date": "2015-01-01 23:00:00+00:00",
            },
            {
                "origin": "https://github.com/user1/repo1",
                "visit": "2",
                "date": "2017-01-01 23:00:00+00:00",
            },
            {"url": "https://github.com/user2/repo1"},
            {
                "origin": "https://github.com/user2/repo1",
                "date": "2015-01-01 23:00:00+00:00",
            },
            {
                "origin": "https://github.com/user2/repo1",
                "visit": "1",
                "date": "2015-01-01 23:00:00+00:00",
            },
        ]
    )
    assert obj_unique_keys == expected_unique_keys
