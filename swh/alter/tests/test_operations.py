# Copyright (C) 2023-2024 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

from datetime import datetime, timedelta, timezone
import itertools
import logging
import operator
import shutil
import subprocess
import textwrap
from typing import Any, List, Set
from unittest.mock import call

import pytest
import yaml

from swh.model.model import BaseModel, Origin
from swh.model.swhids import CoreSWHID, ExtendedObjectType, ExtendedSWHID
from swh.objstorage.interface import ObjStorageInterface
from swh.search.interface import SearchInterface
from swh.storage.interface import StorageInterface
from swh.storage.proxies.masking.db import MaskedState

from ..mirror_notification_watcher import MASKING_REQUEST_IDENTIFIER_PREFIX
from ..operations import MaskingRequestNotFound, Removable, Remover, RemoverError
from ..recovery_bundle import SecretSharing
from .conftest import (
    OBJECT_SECRET_KEY,
    TWO_GROUPS_REQUIRED_WITH_ONE_MINIMUM_SHARE_EACH_SECRET_SHARING_YAML,
)


@pytest.fixture
def remover(
    sample_populated_storage,
    graph_client_with_only_initial_origin,
):
    return Remover(
        storage=sample_populated_storage,
        graph_client=graph_client_with_only_initial_origin,
        known_missing=[
            ExtendedSWHID.from_string(
                "swh:1:cnt:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            )
        ],
    )


def test_remover_get_removable(remover):
    swhids = [
        ExtendedSWHID.from_string("swh:1:ori:83404f995118bd25774f4ac14422a8f175e7a054"),
        ExtendedSWHID.from_string("swh:1:ori:8f50d3f60eae370ddbf85c86219c55108a350165"),
    ]
    removable = remover.get_removable(swhids)
    assert len(removable.removable_swhids) == 33
    assert len(removable.referencing) == 0


def test_remover_get_removable_populates_referencing(remover):
    swhids = [
        ExtendedSWHID.from_string("swh:1:ori:8f50d3f60eae370ddbf85c86219c55108a350165"),
    ]
    removable = remover.get_removable(swhids)
    assert set(removable.referencing) == {
        ExtendedSWHID.from_string(s)
        for s in (
            "swh:1:rel:0000000000000000000000000000000000000010",
            "swh:1:rev:0000000000000000000000000000000000000009",
            "swh:1:dir:0000000000000000000000000000000000000008",
        )
    }


def test_remover_get_removable_with_known_missing(
    sample_populated_storage,
    graph_client_with_both_origins,
):
    swhids = [
        ExtendedSWHID.from_string("swh:1:ori:83404f995118bd25774f4ac14422a8f175e7a054"),
        ExtendedSWHID.from_string("swh:1:ori:8f50d3f60eae370ddbf85c86219c55108a350165"),
    ]
    remover = Remover(
        storage=sample_populated_storage,
        graph_client=graph_client_with_both_origins,
        known_missing=swhids[1:],
    )
    removable = remover.get_removable(swhids)
    assert removable.removable_swhids == [
        ExtendedSWHID.from_string(s)
        for s in (
            "swh:1:ori:83404f995118bd25774f4ac14422a8f175e7a054",
            "swh:1:snp:0000000000000000000000000000000000000020",
            "swh:1:emd:ba1e287385aac8d76caaf9956819a5d68bfe2083",
            "swh:1:emd:bfe476f7cffb00a5be2b12cfb364e207e4be0da2",
            "swh:1:emd:1ecd328c7597043895621da4d5351c59f1de663c",
            "swh:1:emd:bcfe01c5e96a675b500d32b15b4ea36bd5a46cdb",
        )
    ]
    assert set(removable.referencing) == {
        ExtendedSWHID.from_string(s)
        for s in (
            "swh:1:rev:0000000000000000000000000000000000000009",
            "swh:1:rel:0000000000000000000000000000000000000010",
        )
    }


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
    sample_populated_storage,
):
    swhids = [
        ExtendedSWHID.from_string(s)
        for s in (
            "swh:1:ori:8f50d3f60eae370ddbf85c86219c55108a350165",
            "swh:1:snp:0000000000000000000000000000000000000022",
            "swh:1:rel:0000000000000000000000000000000000000021",
            "swh:1:rev:0000000000000000000000000000000000000018",
            "swh:1:rev:0000000000000000000000000000000000000013",
            "swh:1:dir:0000000000000000000000000000000000000017",
            "swh:1:cnt:0000000000000000000000000000000000000015",
            "swh:1:cnt:0000000000000000000000000000000000000014",
        )
    ]
    referencing = [
        ExtendedSWHID.from_string(s)
        for s in (
            "swh:1:rel:0000000000000000000000000000000000000010",
            "swh:1:rev:0000000000000000000000000000000000000009",
            "swh:1:dir:0000000000000000000000000000000000000012",
        )
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
        requested=[swhids[0]],
        removable=Removable(removable_swhids=swhids, referencing=referencing),
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
        ExtendedSWHID.from_string(s)
        for s in ("swh:1:ori:8f50d3f60eae370ddbf85c86219c55108a350165",)
    ]
    bundle_path = tmp_path / "test.swh-recovery-bundle"
    expire = datetime.fromisoformat("2001-01-01").astimezone()
    with pytest.raises(RemoverError, match="Unable to set expiration date"):
        remover.create_recovery_bundle(
            secret_sharing=SecretSharing.from_dict(secret_sharing_conf),
            requested=[swhids[0]],
            removable=Removable(removable_swhids=swhids, referencing=[]),
            recovery_bundle_path=bundle_path,
            removal_identifier="test",
            reason="doing a test",
            expire=expire,
        )


def test_remover_remove(
    mocker,
    sample_populated_storage,
    graph_client_with_only_initial_origin,
):
    removal_storage_one = mocker.MagicMock()
    removal_storage_one.object_delete.return_value = {"origin:delete": 0}
    removal_storage_one.extid_delete_for_target.return_value = {"extid:delete": 0}
    removal_storage_two = mocker.MagicMock()
    removal_storage_two.object_delete.return_value = {"origin:delete": 0}
    removal_storage_two.extid_delete_for_target.return_value = {"extid:delete": 0}
    remover = Remover(
        sample_populated_storage,
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
    sample_populated_storage,
):
    from swh.objstorage.interface import objid_from_dict

    storage = sample_populated_storage
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


def test_remover_remove_from_flaping_objstorages(
    mocker,
    sample_populated_storage,
):
    from swh.objstorage.interface import objid_from_dict

    storage = sample_populated_storage
    mocker.patch("swh.alter.operations.time.sleep")
    objstorage = mocker.Mock(spec=ObjStorageInterface)
    objstorage.delete.side_effect = itertools.cycle([Exception(), Exception(), None])
    graph_client = mocker.MagicMock()
    remover = Remover(
        storage,
        graph_client,
        removal_objstorages={"flaping": objstorage},
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
    assert len(objstorage.delete.call_args_list) == 3


def test_remover_remove_from_faulty_objstorages(
    mocker,
    caplog,
    sample_populated_storage,
):
    from swh.objstorage.interface import objid_from_dict

    storage = sample_populated_storage
    mocker.patch("swh.alter.operations.time.sleep")
    objstorage = mocker.Mock(spec=ObjStorageInterface)
    objstorage.delete.side_effect = Exception("error")
    graph_client = mocker.MagicMock()
    remover = Remover(
        storage,
        graph_client,
        removal_objstorages={
            "faulty": objstorage,
        },
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
    with caplog.at_level(logging.WARNING):
        with pytest.raises(Exception, match="error"):
            remover.remove()
    assert len(objstorage.delete.call_args_list) == 3
    assert (
        "objstorage “faulty” raised “Exception('error')” during attempt 2, "
        "retrying in 10 seconds…" in caplog.text
    )


def test_remover_remove_from_objstorages_object_missing_from_one_objstorage(
    caplog,
    mocker,
    sample_populated_storage,
):
    from swh.objstorage.exc import ObjNotFoundError
    from swh.objstorage.interface import objid_from_dict

    storage = sample_populated_storage
    objstorage1 = mocker.Mock(spec=ObjStorageInterface)
    objstorage2 = mocker.Mock(spec=ObjStorageInterface)
    objstorage2.delete.side_effect = ObjNotFoundError()
    graph_client = mocker.MagicMock()
    remover = Remover(
        storage,
        graph_client,
        removal_objstorages={"one": objstorage1, "two": objstorage2},
    )
    contents = storage.content_get(
        [bytes.fromhex("0000000000000000000000000000000000000014")], algo="sha1_git"
    )
    remover.objids_to_remove = [
        objid_from_dict(content.to_dict()) for content in contents
    ]
    with caplog.at_level(logging.INFO):
        remover.remove_from_objstorages()
    # We should not get an error message for a single objstorage.
    # Rationale: more objstorages have been added as time went
    # on. But while old objects have not been moved to newer
    # objstorages, they are still available. The real problem
    # is when not a single objstorage has a particular object.
    # (See the test below.)
    assert not any("not found" in msg for msg in caplog.messages)


def test_remover_remove_from_objstorages_object_missing_from_all_objstorages(
    caplog,
    mocker,
    sample_populated_storage,
):
    from swh.objstorage.exc import ObjNotFoundError
    from swh.objstorage.interface import objid_from_dict

    storage = sample_populated_storage
    objstorage1 = mocker.Mock(spec=ObjStorageInterface)
    objstorage1.delete.side_effect = ObjNotFoundError()
    objstorage2 = mocker.Mock(spec=ObjStorageInterface)
    objstorage2.delete.side_effect = ObjNotFoundError()
    graph_client = mocker.MagicMock()
    remover = Remover(
        storage,
        graph_client,
        removal_objstorages={"one": objstorage1, "two": objstorage2},
    )
    contents = storage.content_get(
        [bytes.fromhex("0000000000000000000000000000000000000014")], algo="sha1_git"
    )
    remover.objids_to_remove = [
        objid_from_dict(content.to_dict()) for content in contents
    ]
    with caplog.at_level(logging.INFO):
        remover.remove_from_objstorages()
    expected = textwrap.dedent(
        """\
        Objects not found in any objstorage:
        | blake2s256                                                       | sha1                                     | sha1_git                                 | sha256                                                           |
        |------------------------------------------------------------------|------------------------------------------|------------------------------------------|------------------------------------------------------------------|
        | 0000000000000000000000000000000000000000000000000000000000000014 | 0000000000000000000000000000000000000014 | 0000000000000000000000000000000000000014 | 0000000000000000000000000000000000000000000000000000000000000014 |
        """.rstrip()  # noqa: B950
    )
    assert expected == caplog.records[-1].message


def test_remover_remove_from_objstorage_display_timings(
    caplog,
    mocker,
    sample_populated_storage,
):
    from swh.objstorage.interface import objid_from_dict

    storage = sample_populated_storage
    objstorage = mocker.Mock(spec=ObjStorageInterface)
    graph_client = mocker.MagicMock()
    remover = Remover(
        storage,
        graph_client,
        removal_objstorages={"objstorage": objstorage},
    )
    remover.swhids_to_remove = [
        ExtendedSWHID.from_string("swh:1:ori:8f50d3f60eae370ddbf85c86219c55108a350165"),
    ]
    contents = storage.content_get(
        [
            bytes.fromhex("0000000000000000000000000000000000000007"),
            bytes.fromhex("0000000000000000000000000000000000000011"),
            bytes.fromhex("0000000000000000000000000000000000000014"),
        ],
        algo="sha1_git",
    )
    mocker.patch("time.monotonic", side_effect=[0.001, 0.2, 0.3, 0.4, 0.5, 0.72])
    remover.objids_to_remove = [
        objid_from_dict(content.to_dict()) for content in contents
    ]
    with caplog.at_level(logging.INFO):
        remover.remove()
    assert caplog.messages[-2] == (
        "3 objects removed from objstorage “objstorage”. "
        "Total time: 519 milliseconds, "
        "average: 173 milliseconds per object, "
        "standard deviation: 64.09 milliseconds"
    )


def test_remover_remove_from_searches(
    mocker,
    sample_populated_storage,
):
    storage = sample_populated_storage
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
    sample_populated_storage,
    remover,
):
    storage = sample_populated_storage
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
        wraps=lambda s, _: (
            [
                ExtendedSWHID.from_string(
                    "swh:1:rev:0000000000000000000000000000000000000003"
                )
            ]
            if s.object_type == ExtendedObjectType.DIRECTORY
            else []
        ),
    )
    result = remover.have_new_references(
        [ExtendedSWHID.from_string(swhid) for swhid in swhids]
    )
    assert result is True


def test_remover_have_new_references_inside_removed(
    mocker,
    sample_populated_storage,
    remover,
):
    storage = sample_populated_storage
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
        wraps=lambda s, _: (
            [
                ExtendedSWHID.from_string(
                    "swh:1:rev:0000000000000000000000000000000000000013"
                )
            ]
            if s.object_type == ExtendedObjectType.DIRECTORY
            else []
        ),
    )
    result = remover.have_new_references(
        [ExtendedSWHID.from_string(swhid) for swhid in swhids]
    )
    assert result is False


def test_remover_have_new_references_nothing_new(
    mocker,
    sample_populated_storage,
    remover,
):
    storage = sample_populated_storage
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


def test_remover_have_new_references_missing_from_storage(
    mocker,
    sample_populated_storage,
    remover,
):
    storage = sample_populated_storage
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
    # Patch `object_find_recent_references()` to return a SWHID
    # that does not exist in the storage. This imitates a stale
    # entry in the `object_references` table.
    mocker.patch.object(
        storage,
        "object_find_recent_references",
        wraps=lambda s, _: (
            [
                ExtendedSWHID.from_string(
                    "swh:1:rev:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                )
            ]
            if s.object_type == ExtendedObjectType.DIRECTORY
            else []
        ),
    )
    result = remover.have_new_references(
        [ExtendedSWHID.from_string(swhid) for swhid in swhids]
    )
    # As the reference actually does not exist, this means
    # no new references have actually been made since we
    # started the process.
    assert result is False


def test_remover_remove_fails_when_new_references_have_been_added(
    mocker,
    sample_populated_storage,
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
    sample_populated_storage,
    graph_client_with_only_initial_origin,
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
        storage=sample_populated_storage,
        graph_client=graph_client_with_only_initial_origin,
        restoration_storage=restoration_storage,
    )

    swhids = [
        ExtendedSWHID.from_string("swh:1:ori:8f50d3f60eae370ddbf85c86219c55108a350165")
    ]
    remover.create_recovery_bundle(
        secret_sharing=SecretSharing.from_dict(secret_sharing_conf),
        requested=[swhids[0]],
        removable=Removable(removable_swhids=swhids, referencing=[]),
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
    sample_populated_storage,
    graph_client_with_only_initial_origin,
    tmp_path,
):
    mock = mocker.patch("swh.alter.operations.RecoveryBundle", autospec=True)
    instance = mock.return_value
    instance.restore.return_value = {"origin:add": 1}
    restoration_storage = mocker.Mock(spec=StorageInterface)

    remover = Remover(
        storage=sample_populated_storage,
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
    sample_recovery_bundle_path,
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


def test_remover_handle_removal_notification_with_removal(
    mocker,
    tmp_path,
    sample_populated_storage_with_matching_hash,
    empty_graph_client,
    populated_masking_admin,
    example_removal_notification_with_matching_hash,
    secret_sharing_conf,
):
    storage = sample_populated_storage_with_matching_hash
    skipped_content_swhid = ExtendedSWHID.from_string(
        # SkippedContent
        "swh:1:cnt:33e45d56f88993aae6a0198013efa80716fd8920"
    )
    removable_swhids = example_removal_notification_with_matching_hash.removed_objects
    removable_swhids.remove(skipped_content_swhid)

    referencing = [
        ExtendedSWHID.from_string(s)
        for s in (
            "swh:1:cnt:36fade77193cb6d2bd826161a0979d64c28ab4fa",
            "swh:1:dir:8505808532953da7d2581741f01b29c04b1cb9ab",
        )
    ]

    masking_admin = populated_masking_admin
    notification_removal_identifier = (
        example_removal_notification_with_matching_hash.removal_identifier
    )
    recovery_bundle_path = tmp_path / "test.swh-bundle"
    remover = Remover(
        storage=storage,
        restoration_storage=storage,
        graph_client=empty_graph_client,
        masking_admin=masking_admin,
    )
    mock_get_removable = mocker.patch.object(
        remover,
        "get_removable",
        return_value=Removable(
            removable_swhids=removable_swhids, referencing=referencing
        ),
    )
    mocker.patch.object(remover, "have_new_references", return_value=False)

    remover.handle_removal_notification_with_removal(
        notification_removal_identifier=notification_removal_identifier,
        secret_sharing=SecretSharing.from_dict(secret_sharing_conf),
        recovery_bundle_path=recovery_bundle_path,
        ignore_requested=[
            Origin(url="https://github.com/user1/repo1"),
            ExtendedSWHID.from_string(
                "swh:1:ori:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            ),
        ],
    )

    mock_get_removable.assert_called_once_with(
        [
            ExtendedSWHID.from_string(
                "swh:1:ori:9147ab9c9287940d4fdbe95d8780664d7ad2dfc0"
            )
        ]
    )

    with masking_admin.conn:
        masking_request = masking_admin.find_request(
            f"{MASKING_REQUEST_IDENTIFIER_PREFIX}{notification_removal_identifier}"
        )
        masking_states = masking_admin.get_states_for_request(masking_request.id)
        assert masking_states == {
            swhid: MaskedState.VISIBLE for swhid in removable_swhids
        } | {skipped_content_swhid: MaskedState.DECISION_PENDING}
        history = masking_admin.get_history(masking_request.id)
        assert list(sorted(history, key=operator.attrgetter("date")))[
            -1
        ].message == textwrap.dedent(
            """\
            Made 17 objects visible again after removal.

            Objects in state “decision pending” that were not removed:
            - swh:1:cnt:33e45d56f88993aae6a0198013efa80716fd8920"""
        )


def test_remover_handle_removal_notification_with_removal_masked_request_not_found(
    tmp_path,
    sample_populated_storage_with_matching_hash,
    empty_graph_client,
    populated_masking_admin,
    example_removal_notification_with_matching_hash,
    secret_sharing_conf,
):
    storage = sample_populated_storage_with_matching_hash
    remover = Remover(
        storage=storage,
        restoration_storage=storage,
        graph_client=empty_graph_client,
        masking_admin=populated_masking_admin,
    )
    recovery_bundle_path = tmp_path / "test.swh-bundle"
    with pytest.raises(MaskingRequestNotFound, match="NON_EXISTENT"):
        remover.handle_removal_notification_with_removal(
            notification_removal_identifier="NON_EXISTENT",
            secret_sharing=SecretSharing.from_dict(secret_sharing_conf),
            recovery_bundle_path=recovery_bundle_path,
        )


@pytest.mark.parametrize(
    "masked_status, expected_message",
    [
        (MaskedState.RESTRICTED, "Made 18 objects permanently restricted."),
        (
            MaskedState.DECISION_PENDING,
            "Made 18 objects restricted until a decision is made.",
        ),
        (MaskedState.VISIBLE, "Made 18 objects visible again."),
    ],
)
def test_handle_removal_notification_by_changing_masked_status(
    masked_status,
    expected_message,
    sample_populated_storage_with_matching_hash,
    empty_graph_client,
    populated_masking_admin,
    example_removal_notification_with_matching_hash,
):
    storage = sample_populated_storage_with_matching_hash
    masking_admin = populated_masking_admin
    remover = Remover(
        storage=storage,
        restoration_storage=storage,
        graph_client=empty_graph_client,
        masking_admin=masking_admin,
    )
    notification_removal_identifier = (
        example_removal_notification_with_matching_hash.removal_identifier
    )
    remover.handle_removal_notification_by_changing_masked_status(
        notification_removal_identifier=notification_removal_identifier,
        masked_state=masked_status,
    )
    with masking_admin.conn:
        masking_request = masking_admin.find_request(
            f"{MASKING_REQUEST_IDENTIFIER_PREFIX}{notification_removal_identifier}"
        )
        history = masking_admin.get_history(masking_request.id)
        assert (
            list(sorted(history, key=operator.attrgetter("date")))[-1].message
            == expected_message
        )
        assert all(
            status == masked_status
            for status in masking_admin.get_states_for_request(
                masking_request.id
            ).values()
        )


def test_handle_removal_notification_by_changing_masked_status_masked_request_not_found(
    sample_populated_storage_with_matching_hash,
    empty_graph_client,
    populated_masking_admin,
):
    storage = sample_populated_storage_with_matching_hash
    remover = Remover(
        storage=storage,
        restoration_storage=storage,
        graph_client=empty_graph_client,
        masking_admin=populated_masking_admin,
    )
    with pytest.raises(MaskingRequestNotFound, match="NON_EXISTENT"):
        remover.handle_removal_notification_by_changing_masked_status(
            notification_removal_identifier="NON_EXISTENT",
            masked_state=MaskedState.RESTRICTED,
        )
