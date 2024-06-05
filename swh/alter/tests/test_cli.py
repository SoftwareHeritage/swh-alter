# Copyright (C) 2023 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

from contextlib import closing
from datetime import datetime, timedelta
import logging
import os
import shutil
import socket
import sys

from click.testing import CliRunner
import pytest
import yaml

from swh.model.swhids import ExtendedSWHID

from ..cli import (
    alter_cli_group,
    extract_content,
    info,
    list_candidates,
    recover_decryption_key,
    remove,
    restore,
    resume_removal,
    rollover,
)
from ..operations import Remover
from ..recovery_bundle import AgeSecretKey, age_decrypt
from .test_inventory import (  # noqa
    directory_6_with_multiple_entries_pointing_to_the_same_content,
    snapshot_20_with_multiple_branches_pointing_to_the_same_head,
)
from .test_inventory import graph_client_with_only_initial_origin  # noqa: F401
from .test_inventory import origin_with_submodule  # noqa: F401
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
from .test_recovery_bundle import sample_recovery_bundle_path  # noqa: F401
from .test_removable import inventory_from_forked_origin  # noqa: F401
from .test_removable import storage_with_references_from_forked_origin  # noqa: F401

DEFAULT_CONFIG = {
    "storage": {
        "cls": "memory",
        "objstorage": {
            "cls": "memory",
        },
    },
    "graph": {
        "url": "http://granet.internal.softwareheritage.org:5009/graph",
        # timeout is in seconds
        # see https://requests.readthedocs.io/en/latest/user/advanced/#timeouts
        "timeout": 10,
    },
    "recovery_bundles": {
        "secret_sharing": {
            "minimum_required_groups": 2,
            "groups": {},
        }
    },
}


@pytest.fixture
def mocked_external_resources(
    mocker,
    graph_client_with_only_initial_origin,  # noqa: F811
    storage_with_references_from_forked_origin,  # noqa: F811
):
    mocker.patch.object(storage_with_references_from_forked_origin, "content_get")
    mocker.patch(
        "swh.storage.get_storage",
        return_value=storage_with_references_from_forked_origin,
    )
    mocker.patch(
        "swh.graph.http_client.RemoteGraphClient",
        return_value=graph_client_with_only_initial_origin,
    )


@pytest.fixture
def remove_config():
    config = dict(DEFAULT_CONFIG)
    config["restoration_storage"] = {
        "cls": "memory",
        "journal_writer": {
            "cls": "memory",
            "anonymize": True,
        },
    }
    config["removal_searches"] = {
        "memory": {
            "cls": "memory",
        },
    }
    config["removal_storages"] = {
        "memory": {
            "cls": "memory",
        },
    }
    config["removal_objstorages"] = {
        "memory": {
            "cls": "memory",
        },
    }
    config["removal_journals"] = {
        "example": {
            "cls": "kafka",
            "brokers": [
                "kafka1.example.org",
            ],
            "prefix": "swh.journal.objects",
            "client_id": "swh.alter.removals",
        },
    }
    config["recovery_bundles"] = yaml.safe_load(
        TWO_GROUPS_REQUIRED_WITH_ONE_MINIMUM_SHARE_EACH_SECRET_SHARING_YAML
    )
    return config


@pytest.fixture
def remove_config_path(tmp_path, remove_config):
    remove_config_path = tmp_path / "swh-config.yml"
    remove_config_path.write_text(yaml.dump(remove_config))
    return str(remove_config_path)


@pytest.fixture
def capture_output(mocker, caplog):
    # We patch our loggers so they can return to their original
    # configuration after the test
    for module in ("swh.alter.operations", "swh.alter.recovery_bundle"):
        mocker.patch.object(
            sys.modules[module], "logger", logging.getLogger(f"{module}.tests")
        )

    # At a higher level we won’t get the right messages in the output
    caplog.set_level(logging.INFO)

    return caplog


def test_cli_remove_dry_run_fails_without_mode(remove_config):
    runner = CliRunner()
    result = runner.invoke(
        remove,
        [
            "--identifier",
            "test",
            "--recovery-bundle",
            "/nonexistent",
            "--dry-run",
            "swh:1:ori:cafecafecafecafecafecafecafecafecafecafe",
        ],
        obj={"config": remove_config},
        catch_exceptions=False,
    )
    assert "Invalid value for '--dry-run'" in result.output
    assert result.exit_code == 2


def test_cli_remove_dry_run_stop_before_recovery_bundle(
    mocker, mocked_external_resources, remove_config
):
    removable_swhids = [
        ExtendedSWHID.from_string("swh:1:ori:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ExtendedSWHID.from_string("swh:1:ori:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
    ]
    mocker.patch.object(Remover, "get_removable", return_value=removable_swhids)
    create_recovery_bundle_method = mocker.patch.object(
        Remover, "create_recovery_bundle"
    )
    remove_method = mocker.patch.object(Remover, "remove")
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(
            remove,
            [
                "--identifier",
                "test",
                "--recovery-bundle",
                "/nonexistent",
                "--dry-run=stop-before-recovery-bundle",
                "swh:1:ori:cafecafecafecafecafecafecafecafecafecafe",
            ],
            obj={"config": remove_config},
            catch_exceptions=False,
        )
    assert result.exit_code == 0
    assert "We would remove 2 objects" in result.output
    create_recovery_bundle_method.assert_not_called()
    remove_method.assert_not_called()


def test_cli_remove_dry_run_stop_before_removal(
    mocker,
    mocked_external_resources,
    remove_config,
    tmp_path,
):
    removable_swhids = [
        ExtendedSWHID.from_string("swh:1:ori:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ExtendedSWHID.from_string("swh:1:ori:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
    ]
    mocker.patch.object(Remover, "get_removable", return_value=removable_swhids)
    create_recovery_bundle_method = mocker.patch.object(
        Remover, "create_recovery_bundle"
    )
    remove_method = mocker.patch.object(Remover, "remove")
    runner = CliRunner()
    result = runner.invoke(
        remove,
        [
            "--identifier",
            "test",
            "--recovery-bundle",
            str(tmp_path / "bundle"),
            "--dry-run=stop-before-removal",
            "swh:1:ori:cafecafecafecafecafecafecafecafecafecafe",
        ],
        obj={"config": remove_config},
        catch_exceptions=False,
    )
    assert result.exit_code == 0
    create_recovery_bundle_method.assert_called_once()
    remove_method.assert_not_called()


def test_cli_remove_display_decryption_key(
    capture_output,
    mocker,
    mocked_external_resources,
    remove_config_path,
    tmp_path,
):
    mocker.patch.object(Remover, "get_removable", return_value=[])
    mocker.patch.object(
        Remover, "create_recovery_bundle", return_value="SUPER-SECRET-KEY"
    )
    mocker.patch.object(Remover, "remove")
    runner = CliRunner()
    result = runner.invoke(
        alter_cli_group,
        [
            "remove",
            "--identifier",
            "test",
            "--recovery-bundle",
            str(tmp_path / "bundle"),
            "--dry-run=stop-before-removal",
            "swh:1:ori:cafecafecafecafecafecafecafecafecafecafe",
        ],
        env={"SWH_CONFIG_FILENAME": remove_config_path},
        catch_exceptions=False,
    )
    assert result.exit_code == 0
    assert "Recovery bundle decryption key: SUPER-SECRET-KEY" in result.output


def test_cli_remove_colored_output(
    capture_output, mocker, mocked_external_resources, remove_config_path
):
    import click

    runner = CliRunner()
    result = runner.invoke(
        alter_cli_group,
        [
            "remove",
            "--identifier",
            "test",
            "--recovery-bundle",
            "/nonexistent",
            "--dry-run=stop-before-recovery-bundle",
            "swh:1:ori:8f50d3f60eae370ddbf85c86219c55108a350165",
        ],
        env={"SWH_CONFIG_FILENAME": remove_config_path},
        color=True,
        catch_exceptions=False,
    )
    assert result.exit_code == 0
    assert click.style("Finding removable objects…", fg="cyan") in result.output


def find_free_port():
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("localhost", 0))
        # We explicitly not set SO_REUSEADDR because we want the port
        # to stay free so we can get our connection refused.
        return s.getsockname()[1]


def test_cli_remove_errors_when_graph_is_down(
    mocker,
    storage_with_references_from_forked_origin,  # noqa: F811
    remove_config,
):
    mocker.patch(
        "swh.storage.get_storage",
        return_value=storage_with_references_from_forked_origin,
    )
    erroneous_graph_port = find_free_port()
    remove_config["graph"]["url"] = f"http://localhost:{erroneous_graph_port}/graph"

    runner = CliRunner()
    result = runner.invoke(
        remove,
        [
            "--identifier",
            "test",
            "--recovery-bundle",
            "/nonexistent",
            "--dry-run=stop-before-recovery-bundle",
            "swh:1:ori:cafecafecafecafecafecafecafecafecafecafe",
        ],
        obj={"config": remove_config},
    )
    assert result.exit_code == 1, result.output
    assert "Unable to connect to the graph server" in result.output


def test_cli_remove_origin_conversions(
    mocker, mocked_external_resources, remove_config
):
    mocker.patch.object(Remover, "get_removable", return_value=[])
    runner = CliRunner()
    runner.invoke(
        remove,
        [
            "--identifier",
            "test",
            "--recovery-bundle",
            "/nonexistent",
            "--dry-run=stop-before-recovery-bundle",
            "https://example.com/swh/graph",
            "swh:1:ori:8f50d3f60eae370ddbf85c86219c55108a350165",
        ],
        obj={"config": remove_config},
        catch_exceptions=False,
    )
    args, _ = Remover.get_removable.call_args
    assert set(args[0]) == {
        ExtendedSWHID.from_string("swh:1:ori:83404f995118bd25774f4ac14422a8f175e7a054"),
        ExtendedSWHID.from_string("swh:1:ori:8f50d3f60eae370ddbf85c86219c55108a350165"),
    }


def test_cli_remove_output_subgraphs(mocker, mocked_external_resources, remove_config):
    mocker.patch.object(Remover, "get_removable", return_value=[])
    swhid = "swh:1:ori:8f50d3f60eae370ddbf85c86219c55108a350165"
    runner = CliRunner()
    runner.invoke(
        remove,
        [
            "--identifier",
            "test",
            "--recovery-bundle",
            "/nonexistent",
            "--dry-run=stop-before-recovery-bundle",
            "--output-inventory-subgraph=inventory.dot",
            "--output-removable-subgraph=removable.dot",
            "--output-pruned-removable-subgraph=pruned.dot",
            swhid,
        ],
        obj={"config": remove_config},
        catch_exceptions=False,
    )
    Remover.get_removable.assert_called_once()
    args, kwargs = Remover.get_removable.call_args
    assert len(args) == 1
    assert set(args[0]) == {ExtendedSWHID.from_string(swhid)}
    assert kwargs["output_inventory_subgraph"].name == "inventory.dot"
    assert kwargs["output_removable_subgraph"].name == "removable.dot"
    assert kwargs["output_pruned_removable_subgraph"].name == "pruned.dot"


@pytest.fixture
def remove_input_proceed_with_removal():
    return "y\n"


@pytest.fixture
def remover_for_bundle_creation(mocker):
    mocker.patch(
        "swh.storage.get_storage",
        return_value=mocker.MagicMock(),
    )
    mocker.patch(
        "swh.graph.http_client.RemoteGraphClient",
        return_value=mocker.MagicMock(),
    )
    remover = Remover({}, {})
    swhids = [
        ExtendedSWHID.from_string("swh:1:ori:8f50d3f60eae370ddbf85c86219c55108a350165")
    ]
    mocker.patch.object(remover, "get_removable", return_value=swhids)

    def mock_create_recovery_bundle(*args, **kwargs):
        remover.swhids_to_remove = swhids
        remover.journal_objects_to_remove["origin"] = [
            bytes.fromhex("8f50d3f60eae370ddbf85c86219c55108a350165")
        ]
        return "SUPER-SECRET-DECRYPTION-KEY"

    mocker.patch.object(
        remover, "create_recovery_bundle", side_effect=mock_create_recovery_bundle
    )
    mocker.patch("swh.alter.operations.Remover", return_value=remover)
    return remover


def test_cli_remove_create_bundle_no_extra_options(
    remover_for_bundle_creation, remove_config, remove_input_proceed_with_removal
):
    runner = CliRunner()
    runner.invoke(
        remove,
        [
            "--identifier",
            "this-is-not-my-departement",
            "--recovery-bundle",
            "test.swh-recovery-bundle",
            "swh:1:ori:8f50d3f60eae370ddbf85c86219c55108a350165",
        ],
        input=remove_input_proceed_with_removal,
        obj={"config": remove_config},
        catch_exceptions=False,
    )
    remover_for_bundle_creation.create_recovery_bundle.assert_called_once()
    _, kwargs = remover_for_bundle_creation.create_recovery_bundle.call_args
    assert kwargs["removal_identifier"] == "this-is-not-my-departement"
    assert kwargs["recovery_bundle_path"] == "test.swh-recovery-bundle"


def test_cli_remove_create_bundle_with_options(
    remover_for_bundle_creation, remove_config, remove_input_proceed_with_removal
):
    expire = (datetime.now() + timedelta(days=365)).strftime("%Y-%m-%d")
    runner = CliRunner()
    runner.invoke(
        remove,
        [
            "--identifier",
            "test",
            "--recovery-bundle",
            "test.swh-recovery-bundle",
            "--reason",
            "we are doing a test",
            "--expire",
            expire,
            "swh:1:ori:8f50d3f60eae370ddbf85c86219c55108a350165",
        ],
        input=remove_input_proceed_with_removal,
        obj={"config": remove_config},
        catch_exceptions=False,
    )
    remover_for_bundle_creation.create_recovery_bundle.assert_called_once()
    _, kwargs = remover_for_bundle_creation.create_recovery_bundle.call_args
    assert kwargs["removal_identifier"] == "test"
    assert kwargs["recovery_bundle_path"] == "test.swh-recovery-bundle"
    assert kwargs["reason"] == "we are doing a test"
    assert kwargs["expire"] == datetime.fromisoformat(expire).astimezone()


def test_cli_remove_create_bundle_with_expire_unparseable(
    remover_for_bundle_creation,
    remove_config,
):
    runner = CliRunner()
    result = runner.invoke(
        remove,
        [
            "--identifier",
            "test",
            "--expire",
            "garbage",
            "--recovery-bundle",
            "/tmp/nonexistent",
            "swh:1:ori:8f50d3f60eae370ddbf85c86219c55108a350165",
        ],
        obj={"config": remove_config},
        catch_exceptions=False,
    )
    assert result.exit_code != 0
    assert "Invalid value for '--expire'" in result.output


def test_cli_remove_can_be_canceled(
    remover_for_bundle_creation,
    remove_config,
    tmp_path,
):
    runner = CliRunner()
    result = runner.invoke(
        remove,
        [
            "--identifier",
            "test",
            "--recovery-bundle",
            str(tmp_path / "bundle"),
            "swh:1:ori:8f50d3f60eae370ddbf85c86219c55108a350165",
        ],
        input="n\n",
        obj={"config": remove_config},
    )
    assert result.exit_code != 0
    assert "Aborted" in result.output


def test_cli_remove_restores_bundle_when_remove_fails(
    mocker,
    remover_for_bundle_creation,
    remove_config,
    remove_input_proceed_with_removal,
):
    remover = remover_for_bundle_creation

    def fake_remove() -> None:
        from ..operations import RemoverError

        raise RemoverError("let’s pretend something failed during remove")

    mocker.patch.object(remover, "remove", wraps=fake_remove)
    mocker.patch.object(remover, "restore_recovery_bundle")
    runner = CliRunner()
    result = runner.invoke(
        remove,
        [
            "--identifier",
            "this-is-not-my-departement",
            "--recovery-bundle",
            "test.swh-recovery-bundle",
            "swh:1:ori:8f50d3f60eae370ddbf85c86219c55108a350165",
        ],
        input=remove_input_proceed_with_removal,
        obj={"config": remove_config},
        catch_exceptions=False,
    )
    assert result.exit_code == 1
    remover.restore_recovery_bundle.assert_called_once()


def test_cli_list_candidates_omit_referenced(mocked_external_resources, remove_config):
    runner = CliRunner(mix_stderr=False)
    result = runner.invoke(
        list_candidates,
        ["swh:1:ori:8f50d3f60eae370ddbf85c86219c55108a350165"],
        obj={"config": remove_config},
        catch_exceptions=False,
    )
    assert result.exit_code == 0
    assert set(result.stdout.splitlines()) == {
        line.strip()
        for line in """\
        swh:1:ori:8f50d3f60eae370ddbf85c86219c55108a350165
        swh:1:snp:0000000000000000000000000000000000000022
        swh:1:rel:0000000000000000000000000000000000000021
        swh:1:rev:0000000000000000000000000000000000000018
        swh:1:dir:0000000000000000000000000000000000000017
        swh:1:dir:0000000000000000000000000000000000000016
        swh:1:cnt:0000000000000000000000000000000000000015
        swh:1:cnt:0000000000000000000000000000000000000014
        swh:1:rev:0000000000000000000000000000000000000013
        swh:1:dir:0000000000000000000000000000000000000012
        swh:1:cnt:0000000000000000000000000000000000000011
        """.rstrip().splitlines()
    }


def test_cli_list_candidates_no_omit_referenced(
    mocked_external_resources, remove_config
):
    runner = CliRunner(mix_stderr=False)
    result = runner.invoke(
        list_candidates,
        ["--no-omit-referenced", "https://example.com/swh/graph2"],
        obj={"config": remove_config},
        catch_exceptions=False,
    )
    assert result.exit_code == 0
    assert set(result.stdout.splitlines()) == {
        line.strip()
        for line in """\
        swh:1:ori:8f50d3f60eae370ddbf85c86219c55108a350165
        swh:1:snp:0000000000000000000000000000000000000022
        swh:1:rel:0000000000000000000000000000000000000021
        swh:1:rev:0000000000000000000000000000000000000018
        swh:1:dir:0000000000000000000000000000000000000017
        swh:1:dir:0000000000000000000000000000000000000016
        swh:1:cnt:0000000000000000000000000000000000000015
        swh:1:cnt:0000000000000000000000000000000000000014
        swh:1:rev:0000000000000000000000000000000000000013
        swh:1:dir:0000000000000000000000000000000000000012
        swh:1:cnt:0000000000000000000000000000000000000011
        swh:1:rel:0000000000000000000000000000000000000010
        swh:1:rev:0000000000000000000000000000000000000009
        swh:1:dir:0000000000000000000000000000000000000008
        swh:1:cnt:0000000000000000000000000000000000000007
        swh:1:dir:0000000000000000000000000000000000000006
        swh:1:cnt:0000000000000000000000000000000000000005
        swh:1:cnt:0000000000000000000000000000000000000004
        swh:1:rev:0000000000000000000000000000000000000003
        swh:1:dir:0000000000000000000000000000000000000002
        swh:1:cnt:0000000000000000000000000000000000000001
        swh:1:emd:1dd61e73df5a9c9cd422413462f0b623582f23a3
        swh:1:emd:482495bf2a894472462be6b1519bf43509bc2afe
        swh:1:emd:68d8ee6f7c1e6a07f72895d4460917c183fca21c
        swh:1:emd:a777e9317d1241a026f481b662f2b51a37297a32
        swh:1:emd:d54fab7faa95094689f605314763170cf5fa2aa7
        swh:1:emd:f584cf10d8e222ccd1301e70d531d894fd3c3263
        """.rstrip().splitlines()
    }


def test_cli_list_candidates_multiple_swhids(mocked_external_resources, remove_config):
    runner = CliRunner(mix_stderr=False)
    result = runner.invoke(
        list_candidates,
        [
            "--no-omit-referenced",
            "swh:1:dir:0000000000000000000000000000000000000008",
            "swh:1:rev:0000000000000000000000000000000000000003",
        ],
        obj={"config": remove_config},
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output
    assert set(result.stdout.splitlines()) == {
        line.strip()
        for line in """\
        swh:1:dir:0000000000000000000000000000000000000008
        swh:1:cnt:0000000000000000000000000000000000000007
        swh:1:dir:0000000000000000000000000000000000000006
        swh:1:cnt:0000000000000000000000000000000000000005
        swh:1:cnt:0000000000000000000000000000000000000004
        swh:1:dir:0000000000000000000000000000000000000002
        swh:1:rev:0000000000000000000000000000000000000003
        swh:1:cnt:0000000000000000000000000000000000000001
        swh:1:emd:482495bf2a894472462be6b1519bf43509bc2afe
        swh:1:emd:68d8ee6f7c1e6a07f72895d4460917c183fca21c
        swh:1:emd:a777e9317d1241a026f481b662f2b51a37297a32
        swh:1:emd:d54fab7faa95094689f605314763170cf5fa2aa7
        swh:1:emd:f584cf10d8e222ccd1301e70d531d894fd3c3263
        """.rstrip().splitlines()
    }


def test_cli_recovery_bundle_resume_removal_restores_bundle_when_remove_fails(
    request,
    capture_output,
    mocker,
    mocked_external_resources,
    swh_storage,
    sample_data,
    remove_config_path,
    sample_recovery_bundle_path,  # noqa: F811
):
    if "version-1" not in request.keywords:
        # See comment in test_recovery_bundle.py:test_restore()
        swh_storage.metadata_authority_add(sample_data.authorities)
        swh_storage.metadata_fetcher_add(sample_data.fetchers)

    def fake_remove() -> None:
        from ..operations import RemoverError

        raise RemoverError("let’s pretend something failed during remove")

    mocker.patch.object(Remover, "remove", wraps=fake_remove)
    runner = CliRunner()
    result = runner.invoke(
        alter_cli_group,
        [
            "recovery-bundle",
            "resume-removal",
            f"--decryption-key={OBJECT_SECRET_KEY}",
            sample_recovery_bundle_path,
        ],
        env={"SWH_CONFIG_FILENAME": remove_config_path},
        catch_exceptions=False,
    )
    assert result.exit_code == 1, result.output
    assert "Restoring recovery bundle" in result.output
    assert "Something might be wrong" not in result.output


def test_cli_recovery_bundle_extract_content_using_decryption_key_to_file(
    sample_recovery_bundle_path,  # noqa: F811
):
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(
            extract_content,
            [
                "--output=data",
                f"--decryption-key={OBJECT_SECRET_KEY}",
                sample_recovery_bundle_path,
                "swh:1:cnt:d81cc0710eb6cf9efd5b920a8453e1e07157b6cd",
            ],
            obj={"config": DEFAULT_CONFIG},
            catch_exceptions=False,
        )
        assert result.exit_code == 0
        with open("data", "rb") as f:
            assert f.read() == b"42\n"


def test_cli_recovery_bundle_extract_content_using_decryption_key_to_stdout(
    sample_recovery_bundle_path,  # noqa: F811
):
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(
            extract_content,
            [
                "--output=-",
                f"--decryption-key={OBJECT_SECRET_KEY}",
                sample_recovery_bundle_path,
                "swh:1:cnt:d81cc0710eb6cf9efd5b920a8453e1e07157b6cd",
            ],
            obj={"config": DEFAULT_CONFIG},
        )
        assert result.exit_code == 0
        assert result.output == "42\n"


def test_cli_recovery_bundle_extract_content_bad_swhid_argument(
    tmp_path,
    sample_recovery_bundle_path,  # noqa: F811
):
    runner = CliRunner()
    result = runner.invoke(
        extract_content,
        [
            "--output=-",
            f"--decryption-key={OBJECT_SECRET_KEY}",
            sample_recovery_bundle_path,
            "this_is_a_garbage_argument",
        ],
        obj={"config": DEFAULT_CONFIG},
    )
    assert result.exit_code != 0
    assert "expected SWHID" in result.output


def test_cli_recovery_bundle_extract_content_swhid_for_directory(
    tmp_path,
    sample_recovery_bundle_path,  # noqa: F811
):
    runner = CliRunner()
    result = runner.invoke(
        extract_content,
        [
            "--output=-",
            f"--decryption-key={OBJECT_SECRET_KEY}",
            sample_recovery_bundle_path,
            "swh:1:dir:5256e856a0a0898966d6ba14feb4388b8b82d302",
        ],
        obj={"config": DEFAULT_CONFIG},
    )
    assert result.exit_code != 0
    assert "We can only extract data for Content objects" in result.output


def test_cli_recovery_bundle_extract_content_swhid_not_in_bundle(
    tmp_path,
    sample_recovery_bundle_path,  # noqa: F811
):
    runner = CliRunner()
    result = runner.invoke(
        extract_content,
        [
            "--output=-",
            f"--decryption-key={OBJECT_SECRET_KEY}",
            sample_recovery_bundle_path,
            "swh:1:cnt:acab1312acab1312acab1312acab1312acab1312",
        ],
        obj={"config": DEFAULT_CONFIG},
    )
    assert result.exit_code != 0
    assert (
        "“swh:1:cnt:acab1312acab1312acab1312acab1312acab1312” is not in the recovery bundle"
        in result.output
    )


def test_cli_recovery_bundle_extract_content_bad_decryption_key_argument(
    tmp_path,
    sample_recovery_bundle_path,  # noqa: F811
):
    runner = CliRunner()
    result = runner.invoke(
        extract_content,
        [
            "--output=-",
            "--decryption-key=a_garbage_secret_key",
            sample_recovery_bundle_path,
            "swh:1:cnt:d81cc0710eb6cf9efd5b920a8453e1e07157b6cd",
        ],
        obj={"config": DEFAULT_CONFIG},
    )
    assert result.exit_code != 0
    assert "does not look like a decryption key" in result.output


def test_cli_recovery_bundle_extract_content_wrong_decryption_key(
    tmp_path,
    sample_recovery_bundle_path,  # noqa: F811
):
    runner = CliRunner()
    result = runner.invoke(
        extract_content,
        [
            "--output=-",
            "--decryption-key=AGE-SECRET-KEY-1SPTRNLVZYFGVFZ2ZXVUKSEZ6MRP2HNJFCJZGXL8Q3JMA3CJZXPFS9Y7LSD",
            sample_recovery_bundle_path,
            "swh:1:cnt:d81cc0710eb6cf9efd5b920a8453e1e07157b6cd",
        ],
        obj={"config": DEFAULT_CONFIG},
    )
    assert result.exit_code != 0
    assert "Wrong decryption key for this bundle (test_bundle)" in result.output


def test_cli_recovery_bundle_extract_content_non_existent_bundle(tmp_path):
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(
            extract_content,
            [
                "--output=-",
                f"--decryption-key={OBJECT_SECRET_KEY}",
                "non-existent.recovery-bundle",
                "swh:1:cnt:d81cc0710eb6cf9efd5b920a8453e1e07157b6cd",
            ],
            obj={"config": DEFAULT_CONFIG},
        )
        assert result.exit_code != 0
        assert "does not exist" in result.output


@pytest.fixture
def restore_config(swh_storage_backend_config):
    return {
        **DEFAULT_CONFIG,
        "storage": {"cls": "remote", "url": "http://localhost:1"},
        "restoration_storage": swh_storage_backend_config,
    }


@pytest.fixture
def restore_config_path(tmp_path, restore_config):
    restore_config_path = tmp_path / "swh-config.yml"
    restore_config_path.write_text(yaml.dump(restore_config))
    return str(restore_config_path)


def test_cli_recovery_bundle_restore_adds_all_objects(
    request,
    capture_output,
    sample_recovery_bundle_path,  # noqa: F811
    swh_storage,
    sample_data,
    restore_config_path,
):
    if "version-1" not in request.keywords:
        # See comment in test_recovery_bundle.py:test_restore()
        swh_storage.metadata_authority_add(sample_data.authorities)
        swh_storage.metadata_fetcher_add(sample_data.fetchers)
    runner = CliRunner()
    result = runner.invoke(
        alter_cli_group,
        [
            "recovery-bundle",
            "restore",
            f"--decryption-key={OBJECT_SECRET_KEY}",
            sample_recovery_bundle_path,
        ],
        env={"SWH_CONFIG_FILENAME": restore_config_path},
        catch_exceptions=False,
        color=True,
    )
    assert "Content objects added: 2" in result.output
    assert "Total bytes added to objstorage: 10" in result.output
    assert "SkippedContent objects added: 1" in result.output
    assert "Directory objects added: 3" in result.output
    assert "Revision objects added: 2" in result.output
    assert "Release objects added: 2" in result.output
    assert "Snapshot objects added: 2" in result.output
    assert "Origin objects added: 2" in result.output
    if "version-1" not in request.keywords:
        assert "RawExtrinsicMetadata objects for origins added: 2" in result.output
        assert "RawExtrinsicMetadata objects for contents added: 2" in result.output
        assert "ExtID objects added: 2" in result.output


def test_cli_recovery_bundle_restore_from_identity_files(
    capture_output,
    decryption_key_recovery_tests_bundle_path,
    swh_storage,
    restore_config_path,
    env_with_deactivated_age_yubikey_plugin_in_path,
    alabaster_identity_file_path,
    essun_identity_file_path,
    innon_identity_file_path,
):
    runner = CliRunner()
    result = runner.invoke(
        alter_cli_group,
        [
            "recovery-bundle",
            "restore",
            "--identity",
            innon_identity_file_path,
            "--identity",
            alabaster_identity_file_path,
            "--identity",
            essun_identity_file_path,
            decryption_key_recovery_tests_bundle_path,
        ],
        env=env_with_deactivated_age_yubikey_plugin_in_path
        | {"SWH_CONFIG_FILENAME": restore_config_path},
        catch_exceptions=False,
    )
    assert result.exit_code == 0
    assert "Origin objects added: 1" in result.output


def test_cli_recovery_bundle_restore_from_yubikeys(
    capture_output,
    mocker,
    decryption_key_recovery_tests_bundle_path,
    swh_storage,
    restore_config_path,
    env_with_deactivated_age_yubikey_plugin_in_path,
    alabaster_identity_file_path,
    essun_identity_file_path,
    innon_identity_file_path,
):
    # We actually don’t want to rely on YubiKeys so let’s do some mocking and hardcoding
    mocker.patch(
        "swh.alter.recovery_bundle.list_yubikey_identities",
        wraps=fake_list_yubikey_identities,
    )
    mocker.patch("swh.alter.recovery_bundle.age_decrypt", wraps=fake_age_decrypt)

    runner = CliRunner()
    result = runner.invoke(
        alter_cli_group,
        [
            "recovery-bundle",
            "restore",
            decryption_key_recovery_tests_bundle_path,
        ],
        env=env_with_deactivated_age_yubikey_plugin_in_path
        | {"SWH_CONFIG_FILENAME": restore_config_path},
        catch_exceptions=False,
    )
    assert result.exit_code == 0
    assert "Origin objects added: 1" in result.output


def test_cli_recovery_bundle_restore_bad_decryption_key_argument(
    sample_recovery_bundle_path,  # noqa: F811
    swh_storage,
    restore_config,
):
    runner = CliRunner()
    result = runner.invoke(
        restore,
        [
            "--decryption-key=a_garbage_decryption_key",
            sample_recovery_bundle_path,
        ],
        obj={"config": restore_config},
        catch_exceptions=False,
    )
    assert result.exit_code != 0
    assert "does not look like a decryption key" in result.output


def test_cli_recovery_bundle_restore_wrong_decryption_key(
    sample_recovery_bundle_path,  # noqa: F811
    swh_storage,
    restore_config,
):
    runner = CliRunner()
    result = runner.invoke(
        restore,
        [
            "--decryption-key=AGE-SECRET-KEY-1SPTRNLVZYFGVFZ2ZXVUKSEZ6MRP2HNJFCJZGXL8Q3JMA3CJZXPFS9Y7LSD",
            sample_recovery_bundle_path,
        ],
        obj={"config": restore_config},
        catch_exceptions=False,
    )
    assert result.exit_code != 0
    assert "Wrong decryption key for this bundle (test_bundle)" in result.output


def test_cli_recovery_bundle_restore_non_existent_bundle(
    swh_storage,
    restore_config,
):
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(
            restore,
            [
                f"--decryption-key={OBJECT_SECRET_KEY}",
                "non-existent.recovery-bundle",
            ],
            obj={"config": restore_config},
            catch_exceptions=False,
        )
        assert result.exit_code != 0
        assert "does not exist" in result.output


@pytest.fixture
def remover_for_resume_removal(
    mocker,
    storage_with_references_from_forked_origin,  # noqa: F811
    graph_client_with_only_initial_origin,  # noqa: F811
    mocked_external_resources,
):
    remover = Remover(
        storage=storage_with_references_from_forked_origin,
        graph_client=graph_client_with_only_initial_origin,
    )
    mocker.patch.object(remover, "remove", return_value=None)
    mocker.patch("swh.alter.operations.Remover", return_value=remover)
    return remover


def test_cli_recovery_bundle_resume_removal(
    mocker,
    remove_config,
    remover_for_resume_removal,
    sample_recovery_bundle_path,  # noqa: F811
):
    def register_objects_from_bundle(
        recovery_bundle_path: str, object_secret_key: AgeSecretKey
    ):
        assert recovery_bundle_path == sample_recovery_bundle_path
        assert object_secret_key == OBJECT_SECRET_KEY

    remover = remover_for_resume_removal
    mocker.patch.object(
        remover,
        "register_objects_from_bundle",
        side_effect=register_objects_from_bundle,
    )

    runner = CliRunner()
    result = runner.invoke(
        resume_removal,
        [
            f"--decryption-key={OBJECT_SECRET_KEY}",
            sample_recovery_bundle_path,
        ],
        catch_exceptions=False,
        obj={"config": remove_config},
    )
    assert result.exit_code == 0
    remover.register_objects_from_bundle.assert_called_once()
    remover.remove.assert_called_once()


def test_cli_recovery_bundle_resume_removal_prompt_for_key(
    sample_recovery_bundle_path,  # noqa: F811
    remove_config,
    remover_for_resume_removal,
):
    runner = CliRunner()
    result = runner.invoke(
        resume_removal,
        [
            sample_recovery_bundle_path,
        ],
        catch_exceptions=False,
        input=f"{OBJECT_SECRET_KEY}\n",
        obj={"config": remove_config},
    )
    assert result.exit_code == 0
    assert "Decryption key:" in result.output


@pytest.fixture
def complete_manifest_recovery_bundle_path():
    return os.path.join(
        os.path.dirname(__file__), "fixtures", "complete-manifest.swh-recovery-bundle"
    )


EXPECTED_INFO_WITH_COMPLETE_MANIFEST = """\
Recovery bundle “test_bundle”
=============================

Created: 2023-07-27T15:17:13+00:00
Reason: We needed perform some tests.
        Even with a reason on multiple lines.
Expire: 2023-08-27 13:12:00+00:00
List of SWHID objects:
- swh:1:cnt:d81cc0710eb6cf9efd5b920a8453e1e07157b6cd
- swh:1:cnt:c932c7649c6dfa4b82327d121215116909eb3bea
- swh:1:cnt:33e45d56f88993aae6a0198013efa80716fd8920
- swh:1:dir:5256e856a0a0898966d6ba14feb4388b8b82d302
- swh:1:dir:4b825dc642cb6eb9a060e54bf8d69288fbee4904
- swh:1:dir:afa0105cfcaa14fdbacee344e96659170bb1bda5
- swh:1:rev:01a7114f36fddd5ef2511b2cadda237a68adbb12
- swh:1:rev:a646dd94c912829659b22a1e7e143d2fa5ebde1b
- swh:1:rel:f7f222093a18ec60d781070abec4a630c850b837
- swh:1:rel:db81a26783a3f4a9db07b4759ffc37621f159bb2
- swh:1:snp:9b922e6d8d5b803c1582aabe5525b7b91150788e
- swh:1:snp:db99fda25b43dc5cd90625ee4b0744751799c917
- swh:1:ori:33abd4b4c5db79c7387673f71302750fd73e0645
- swh:1:ori:9147ab9c9287940d4fdbe95d8780664d7ad2dfc0
Secret share holders:
- Ali
- Bob
- Camille
- Dlique
"""


def test_cli_recovery_bundle_info(complete_manifest_recovery_bundle_path):
    runner = CliRunner()
    result = runner.invoke(
        info,
        [
            complete_manifest_recovery_bundle_path,
        ],
    )
    assert result.exit_code == 0
    assert result.output == EXPECTED_INFO_WITH_COMPLETE_MANIFEST


EXPECTED_INFO_WITH_ENCRYPTED_SECRETS_VERSION_1 = """\
Recovery bundle “test_bundle”
=============================

Created: 2023-07-27T15:17:13+00:00
List of SWHID objects:
- swh:1:cnt:d81cc0710eb6cf9efd5b920a8453e1e07157b6cd
- swh:1:cnt:c932c7649c6dfa4b82327d121215116909eb3bea
- swh:1:cnt:33e45d56f88993aae6a0198013efa80716fd8920
- swh:1:dir:5256e856a0a0898966d6ba14feb4388b8b82d302
- swh:1:dir:4b825dc642cb6eb9a060e54bf8d69288fbee4904
- swh:1:dir:afa0105cfcaa14fdbacee344e96659170bb1bda5
- swh:1:rev:01a7114f36fddd5ef2511b2cadda237a68adbb12
- swh:1:rev:a646dd94c912829659b22a1e7e143d2fa5ebde1b
- swh:1:rel:f7f222093a18ec60d781070abec4a630c850b837
- swh:1:rel:db81a26783a3f4a9db07b4759ffc37621f159bb2
- swh:1:snp:9b922e6d8d5b803c1582aabe5525b7b91150788e
- swh:1:snp:db99fda25b43dc5cd90625ee4b0744751799c917
- swh:1:ori:33abd4b4c5db79c7387673f71302750fd73e0645
- swh:1:ori:9147ab9c9287940d4fdbe95d8780664d7ad2dfc0
Secret share holders:
- Ali
-----BEGIN AGE ENCRYPTED FILE-----
YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSA5QlBCeXBTbFJyUG43Q0dp
ZzJOMUwzVXNxdnUvWG1xTVNyRlFCUGp2clNzClVjOHp5dktNdGR2NmhqTDk4cC9p
MS8wRUx0THRRaGNEV1B3Mk9OVzI2ZGMKLT4gW3JbM2ItZ3JlYXNlIHsgS1d2Kl0q
Ckw0Y0N1YTNPOWpPaE9FS0FCbjRCS0pPWHZLYUdFSDNONmJlNWdiNnlaOWF3Wkp5
TVRtb2ZOTEttM2dNbmdtSEcKTU1RCi0tLSBDWGFmMnplL3VJVXhlQmpIRUFKYkRD
NDhJSzJoMlhHL0hVOWJjNlpXTldNChIGsGGPCaNS+vMoSEICkMzobdqY9Xi9fcIK
XP6PzJ1sIz4RpPBOq7A4Oj5xYKRhC2ng8KAWaun+gzvCx4Fh6u21ZsyssxYHVTx9
CIgKnOlzrbFlGfEgVFKK+OX+MyRDcVZbZpcpSko8BXh28zEJjLVGhp2YNZZ4yT/+
OPtKJgvooG+i51Mf5Vw9g0jmh97m0K056iPQfS6qukgocl5E/hH2B8HP/ptyT7XI
1kNxxPdJI+pajdVwN9SrMPBfF+meYDMDbtYaa3JH3XxQHefh5D02HAB1Fh8PHRAD
oVbh11BJwO7LmiwfN3PuqfPu7Nj+9+SnJvE8TBKMgeKIuGah
-----END AGE ENCRYPTED FILE-----

- Bob
-----BEGIN AGE ENCRYPTED FILE-----
YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBmZndmS1F4TFRnN3Y2VHIr
dEU2VUFtSjhFQlZXR1N0bWlXOG5BZC9udHg0CjlpRmNTNDBLekQvZThKalQ4ZDFt
WFhHdW9DakIvck1mdHhUWjhsK0NEb0kKLT4gTDstZ3JlYXNlIH5Ud3x0UQpNaEhR
K1BCdVVqNnplREx0V1EKLS0tIE15c09iSm1RZy9WQVoycm96bk1ISTNYNWxlR2Z5
cGt0Ylp1SkxWK2VjMVkKmJD2ZaG06wHSNI52ry9/18j/3dePW1D4wrbMyxvTeTWg
GJFpWLxu5NGYImKNO7qbf0CT6PzerVEiUDUZ94lQfAuONpdZq6sPJzG8abIWx2Lb
1xi9tRVlw+ZxC1RP9l7m6THbiA0jjSbQ6BlCMWPlUG9riH9VjnotTN6mCIR4+yVX
EZZTP0PmXgGM077LDuaEnq5XWriRxmWOvEJoFdU4y95jISeWDk99Gdx4KqeirkSs
0gbuQqXZ/vKjMXggcsMegyostgD9ohHr3MXFEQtYj3J83uoTckGDp4PHcmu3kDll
KmRjPKX4WsQ0SaiXCMkrpLD/gz1z+Vm/MXvsehI=
-----END AGE ENCRYPTED FILE-----

- Camille
-----BEGIN AGE ENCRYPTED FILE-----
YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSAzY29pNmhmaEcwR0FFZFlv
TjBMM1owcWNueUViVkFkNllRdEtxMTVKdDJNCkNFUlgyZkdoeG1TV1o2N09NRW85
d0xDdjMvY2xSU05IT3Z1S0lhTUM1ZXMKLT4gX3AtZ3JlYXNlIEIgWzJCTVx0LQpu
bDBJK3ZOLzdQbjE2Nk5mTC8yMEdRSDc0bUhkZm96R1A0WDlzdlNremlTV2tpcks1
OXNPNXBOVlFpVi8KLS0tICthODlCRjFZR25BM01uR0d6QUxEaUh6eEcxaXpnRk9t
b29sbmhiQzZYOTgKPV71nbIQwDePVvcWov0ZF8ZnJWkBEBCpb8rJ0bkAv8GftVbY
4rJ8U92+hIXaNqlvnDm+VVsFMobgok3JVg0Pk4uVfngJ7gp2icxoVC3azo0cCTII
uj99P6ck1RomAg7VOqP2UnZANP5TDM39+MAgUef1HShyyoW1KujWu/WlnDN9me0J
LB9J6TprPU4Y88YhUKIe4hsxURbQ+aT5yKncfMJr3y4vj9T/99u8rkY4RrAE0JLQ
RTB8WRH6aVaEr8McH4nNcdxEiGuNLFPfjjCczHDdEu4Qi2Y+kX23Zg6oOiFVWnHI
TvqGDkIZSkwPUpcLMXo9p19xQTw3br9IW2mIMoR8N7Q=
-----END AGE ENCRYPTED FILE-----

- Dlique
-----BEGIN AGE ENCRYPTED FILE-----
YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBTNDV4Z2NxV0VESXBYbk8v
SEtPS1E3dTdmNE9aUUtnSlE3c1hSdkNmWndFCkYxeVpwcUk4ZWFqeXpScDlqbDBQ
Ty96NDdrVEdoSkVXazVqdlNkN1dWcmsKLT4gaiVPM11VKS1ncmVhc2UgMVMgaDJF
NGQ8QyBpZiBJaVllZDc8UgpJekoxT1NCb3pNbWoxR0JrL2VVZVI0Mk9BMVJoRDlp
TC9LR1VCbURSNXhYQ0g1NAotLS0gcWxCWXo1SnpOQzFRRE9WN0MvOTdFcXQrM2t4
Nnk0cHR2UU1aYWk3bEI5SQqE/fFM9Mf/vB5pcq3zbYDCcUmxsPUmzzGOGXGa6luj
EYGlb3U1L9/oQ7Lq2SvimX5eun531jERqinqjbbTmUZZoSudFBynHAsG9LpM6ZkW
eJbXRRuWDQjFVs8R+If9OHr1iZSR4CjUD391ReBI0oL+z3raCsRDqMhWVb3UCC3k
A4TasPl0pC9chpNR3ezjMLZJvrVJVW05PWPUeievp46Lm3MmjKxK91YGONDbWA2l
vAcy4mQ2rp1RA7OEjZi6FGMOs1WCnHqC/Wfc80IvkO4dtbnnuq7BmjjZ/t6d2d4w
kjsn91l8dZElvo4XWtMVoedaMaX1zQOnrDeIoKWrSohV+Miosg==
-----END AGE ENCRYPTED FILE-----

"""

EXPECTED_INFO_WITH_ENCRYPTED_SECRETS_VERSION_2 = """\
Recovery bundle “test_bundle”
=============================

Created: 2024-06-03T14:08:55+00:00
List of SWHID objects:
- swh:1:cnt:d81cc0710eb6cf9efd5b920a8453e1e07157b6cd
- swh:1:cnt:c932c7649c6dfa4b82327d121215116909eb3bea
- swh:1:cnt:33e45d56f88993aae6a0198013efa80716fd8920
- swh:1:dir:5256e856a0a0898966d6ba14feb4388b8b82d302
- swh:1:dir:4b825dc642cb6eb9a060e54bf8d69288fbee4904
- swh:1:dir:afa0105cfcaa14fdbacee344e96659170bb1bda5
- swh:1:rev:01a7114f36fddd5ef2511b2cadda237a68adbb12
- swh:1:rev:a646dd94c912829659b22a1e7e143d2fa5ebde1b
- swh:1:rel:f7f222093a18ec60d781070abec4a630c850b837
- swh:1:rel:db81a26783a3f4a9db07b4759ffc37621f159bb2
- swh:1:snp:9b922e6d8d5b803c1582aabe5525b7b91150788e
- swh:1:snp:db99fda25b43dc5cd90625ee4b0744751799c917
- swh:1:ori:33abd4b4c5db79c7387673f71302750fd73e0645
- swh:1:ori:9147ab9c9287940d4fdbe95d8780664d7ad2dfc0
- swh:1:emd:101d70c3574c1e4b730d7ba8e83a4bdadc8691cb
- swh:1:emd:ef3b0865c7a05f79772a3189ddfc8515ec3e1844
- swh:1:emd:43dad4d96edf2fb4f77f0dbf72113b8fe8b5b664
- swh:1:emd:9cafd9348f3a7729c2ef0b9b149ba421589427f0
Secret share holders:
- Ali
-----BEGIN AGE ENCRYPTED FILE-----
YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBNaUNsYjBBdUMram5WdjJY
dzJpc3U1MEtnbC9NRGJoNnlpK0dHVnNvQmxnCjVxOXBEWExqK3o1Yk5VZFN1WVlW
eGppcnVSMG9aZmtkVEVKY2Z1bzczWmMKLT4gXkI0UTpbKy1ncmVhc2UgYjY5Vlwo
CjJ6aFIrYmFjS2xFai9FbGxFUjA3TU14NlZFcTI2dHcwa1JnVncrcU92dDVGemtt
NGFzLzlaUnUwT1lzQjkvV3YKNUUyS2JLMmx4Q1dFRHZkWGhVQWRPdwotLS0gS3Ir
VDFQM1dqVThGNXhOUWg0NUhMK3p6aE4yVzYzdzZTZTRaWGlUN2lWWQqrungtlmC2
ZfPJnq+TWKW/K01h7DGDQG8nFuSrxeO6OYq8wkWDbru8uKIYScmM8OlHl+TKqiyw
SKcRgPdx2R3PlOglyEqYEEIPnUzjlrC3Jfx5pGMut/bq6S56S03mLvpiKV0IHhUG
2HjWp0g/XAFQ4Yf/dk1NUyjpVSkWMRjW1oES1tUrRWVz/q6nJ1Uqn0avd/DEsjNF
lGlW5S/n3WqbRcrZRPh39m200InLeBsGYqt9FtMlePF+KnFYxDzN7wUSsv/ZF+g3
ZJzqFlf1RehWylrQRnv68dRzMbfg1ixd4bA+PujwAk9nH1mwe9g2dDyCNmh6WGQM
cJ3EVQknq+b93XSH2Fr5qxvBzI87nKBDzXfZ6QxjUmbU0pdGgMpoi9PSzBVP
-----END AGE ENCRYPTED FILE-----

- Bob
-----BEGIN AGE ENCRYPTED FILE-----
YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBDdXJJbVFRWWQvSmVVbCt5
K0x1S0kxNjUydFRtbzVpUy9OWFUvUExieVJzCno3MVBGdzJwRDJoU0czYU02dGVs
cllLSzJ6akRtTEdwTmVTc0RNcUxsYVkKLT4gPz8rLmJELWdyZWFzZSBiU2EpPiBL
VVJOIHMjCk0wTHRXb0NUQ3cyWll6WjlGVTR3WUEKLS0tIE1jQU9sRnZSOThxbTlt
QkU2ektkYjc1MXpWaGlpSG9iVHNvam5ZZFUzMHcKHCjzH3sxl3hoNE18ZJioJSoY
O2TH8j8y94Hc+Id5t42UdX89tMKuv5kPyYxWI+EoMgYFIqdwO7btybPjxsQlP0jN
gV2B4gcfqGjiZh6xgURO3r9OuJZkIv3ObFvYJtWbjq9Lzz7shV7fLeQTD2aIflwW
OfiOsLF3j3tzv/17bQUWxzKWLsnwgBgs/W2Elc35b3XgcWcNAQlqgJqYGw7fzZiV
CS9GhRGIQeI1sN/8QL7V2Eu3sSVs2/LMhY/Wu+tNNYKSQsiju+TObXd5iudIAfTy
wMmLmlr4vT3iF1/0KvoIYKq/mGFdQL/j5jMKiFCdAzAEr1raoDxWPj84/lq/Nth/
imU/PsgoTREPwArIX5+qduobiMqf9U5golfLdOdkD05eEg==
-----END AGE ENCRYPTED FILE-----

- Camille
-----BEGIN AGE ENCRYPTED FILE-----
YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBMV1kvY1ZSWlBXejFIU0NB
WUkvdjhzREdXTU5jUGI4V2NzaE40QnNrcUNJCmdHdzhXOHJOaElXSXVrZGhBbERy
MmxMZVM4UjdnWTVqUEgrVDk2YUFRVjgKLT4gJFNBeyFVUFYtZ3JlYXNlIDcgP344
U009RiBAbX19LEs2IFw+Two3dFJaWm1UdTl6TUZxK05Ha3RZaENQc0c2UFVxOGFK
V21jOS9DRFVKSHVZWk9ZMkcrcmJCQkFYbXdZa1pNaG9RClhSWEZtQXpuCi0tLSBI
cms4Sis3eXVxSFp5NG1RSHZUSDBrTFB6WkpQNnJZYVlHR2dOdFBIWWhzCnYYgmEF
CjXAOpi+2MG3L3uqo+9fHms3sb2jyRJFDGHvpkhcYjvO7WmQ2KQW+adhja8ZncMN
GFE0nAv+lueC2oJCZeoMXwkbOPmE+t8rPxFBU+wTqlSGDYa0n6IEuY2loNoZQHKm
y6HbchAeLFczvsXElCupe2L+dc8JWTsi+ZqmCs3G/cLSH/WBnMCBa4erhVtqV16V
sfQLp4XCKI4+THdGhdnSd6pBChSubmYAeV18+eaJsRdVHul8wVD9t3EEa+o3oQ3J
OtD3TYlLc5Kb0Oq3KEQg/CAc0kCxvwZilc96er07PdxVDEusmwB7Eci/CsKMSVnp
lV7CCPlUhLA4QO27+1HgD/sRea1BYR7pXLrEVB+056w6bidg/4jdiJu0KsgHtU1y
7g==
-----END AGE ENCRYPTED FILE-----

- Dlique
-----BEGIN AGE ENCRYPTED FILE-----
YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBtZWR2cDRFcmNPcHF2OWZo
SVVlN1Y1ZTdZYU15cEU1bTVxSVpQWUxER1NJCnhLbVI5M0FvVytnZnp2alBtK1FC
dnNUVWd3ZDVBaHpheFpjVERwN3lqTVEKLT4gIiktZ3JlYXNlIHV+N3hsPyAwbCUg
fGlNNDZjOksKYVZKdk1lelc0WGhnNGwrdUN1aklJZjB5UlUxSmNRCi0tLSBEdmdC
cXVGeHJUb0RkdVBaRVZjSFcwOFpqTDVma3FBUm5Cc1RaS0dLcGJZCmOTJCNSlscr
L5i+voKs1vkc3BuxbxX0n9SIMbxJedIkcsOC84gvuH9F1L/0XuoFa4OmsYuHuwOc
nDJTM6vC+0Zar7PNnOBiqc7CUaqG8MwTsuIEA5E6JA5OTwfLlff/V1XxcL1Uk+Ta
R2YKYfuGIBFUOI2Aplu96zOn09w3MF+6FZK8E+6vl2/PE09267nk1dOoFJnmOY36
N0IEnx8gCboDZgtFVWASe4UUS+ZbHFAwqo7Q/euz2y1wo6WV+miEiOecDSER09WV
iJlYvmOktCmK1Y3Zw66Ytz27P1m03/g+MqpZz4sRVCTkpH4p0JecFd0/q9ukIZfF
01BicZhRGfcfCt3hb/0bEv/kYaYAAmP7Igjxc7tx1tNqtfcGFY5Efr98DCrRTA==
-----END AGE ENCRYPTED FILE-----

"""


def test_cli_recovery_bundle_info_show_encrypted_secrets(
    request,
    sample_recovery_bundle_path,  # noqa: F811
):
    runner = CliRunner()
    result = runner.invoke(
        info,
        [
            "--show-encrypted-secrets",
            sample_recovery_bundle_path,
        ],
    )
    assert result.exit_code == 0
    if "version-1" in request.keywords:
        assert result.output == EXPECTED_INFO_WITH_ENCRYPTED_SECRETS_VERSION_1
    elif "version-2" in request.keywords:
        assert result.output == EXPECTED_INFO_WITH_ENCRYPTED_SECRETS_VERSION_2
    else:
        raise ValueError("Testing an unknown recovery bundle version")


EXPECTED_DUMP_WITH_COMPLETE_MANIFEST = """\
version: 1
removal_identifier: test_bundle
created: 2023-07-27T15:17:13+00:00
swhids:
- swh:1:cnt:d81cc0710eb6cf9efd5b920a8453e1e07157b6cd
- swh:1:cnt:c932c7649c6dfa4b82327d121215116909eb3bea
- swh:1:cnt:33e45d56f88993aae6a0198013efa80716fd8920
- swh:1:dir:5256e856a0a0898966d6ba14feb4388b8b82d302
- swh:1:dir:4b825dc642cb6eb9a060e54bf8d69288fbee4904
- swh:1:dir:afa0105cfcaa14fdbacee344e96659170bb1bda5
- swh:1:rev:01a7114f36fddd5ef2511b2cadda237a68adbb12
- swh:1:rev:a646dd94c912829659b22a1e7e143d2fa5ebde1b
- swh:1:rel:f7f222093a18ec60d781070abec4a630c850b837
- swh:1:rel:db81a26783a3f4a9db07b4759ffc37621f159bb2
- swh:1:snp:9b922e6d8d5b803c1582aabe5525b7b91150788e
- swh:1:snp:db99fda25b43dc5cd90625ee4b0744751799c917
- swh:1:ori:33abd4b4c5db79c7387673f71302750fd73e0645
- swh:1:ori:9147ab9c9287940d4fdbe95d8780664d7ad2dfc0
decryption_key_shares:
  Camille: |
    -----BEGIN AGE ENCRYPTED FILE-----
    YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSAzbm8zY3JKNUZIeXV2MlhV
    TkZ0WExHbCtUbXkrbzZRQ2s3aXM5Y0FqWGxZClBGaDhwbUtST2FYUFVmSzlORngr
    bWFNcnozdDhUeFNrZ3V1dmtzRUgzL1UKLT4gcElmLWdyZWFzZSAiKkprZi13JCA/
    bl8lXjAgKSppQW9tMiAmCkswZzdMQWJySzlnTms5U2tpazBsbExPcndHMXpiVHh4
    NUxVSkxWYVAzOTN0eHlIRjFXVjI1R2wvcSs4RjZQWlYKRXdqcXhlTE96NkpFOThi
    bgotLS0gN05leldQazdmVjNPZzNySFZwUlRwcDJhQmRYdHQxRXV0OXBia2xkNHpi
    MAoOCYUwioybviZxHNgGFNq9+rYLCOnzmbADczDZfGwzfMupFHrg2C6xxjohB4t+
    gxmzDBuJDTf/JhWevOjRKp7rz+0y1JPEGigOtwg6fbIDkZAsiOHV68UOYxWCtpXA
    kQGdMa+z9jjewcJ7nRJsltlu7dYk45AMOq9lH60+/dbbHvzsGfxU5v4b6oiP13sd
    BpgxCzjsobIbMO+IKGGB6t9dtxmFBIrxV5uhBBTdeE9mKN3JES31y0X5tgTp5W7D
    zjrXYvxsXbupKP6voCT1acUe7db6sTgdL1qr68j284mWDI3cD4j2PUI2O44qc7qU
    cumtSZ55JUSIJ7hN+zcUlFC19Qzij7W3/Z5ita0mpQ==
    -----END AGE ENCRYPTED FILE-----
  Dlique: |
    -----BEGIN AGE ENCRYPTED FILE-----
    YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBtMnAwV2llbHhVbUJIcWFy
    cHJ5UVloOU9Zc29vTzJiTU9neHlMR2xrTWtjCldhZGgzNUFHYzQrTjBFUWsyR3pi
    d3VIOElvMmJYVUVzS2h4WjliYU8yZWcKLT4gSSZ5LyR0LWdyZWFzZSBoJyMvICNj
    IExjKVEkCmlSMkxMVjVrWDBOWjVMTXhuUXgzbHF6SEZjR0orR2VzdU9CcGhncG4w
    VjQvT0NtSDFIZGZtZFJ3K1NZU2hSNjAKZlpUZkZyTzBCVS8zSitjb2pjVFBucTRV
    NzR5ZDM2cmVXeUJtCi0tLSBTVE9sZFRua1drT1dBaURaSm1leWU4b08yclJFeWxh
    Z2g1MHZLVEx6MEhVCgUpceAB0I7PJQXR8kn2CzQxuS0cxZffYL2s6AKlL4wd4pSb
    13nBx6FL1/6W8XT1v1CAodvYgLrvdstbEAU3lZmBbGInmXumvh/fCV6gDSRXRkWt
    hMTRRRWXQkkCeBbM6furE/lGsEba+VloE0FL6q2OOqTtV/J81cU3oLxKnWcO//5+
    teQ19uTOMExsiEs5xYSsseRm+qxsUJJ3aVu2fCaFQX39dOatscqek1gS0ZLppTpj
    s6IJcZLsUUVnGJvj/RIECtqKA3IdbCIGdffAqUF+0HIzg9+KU5VhWn9hRMrSB0Dt
    p9qnY8PxRTxEuBXkzulNOaG3quWd7DI418apkYadFNXsFXEWs01fR0Pj
    -----END AGE ENCRYPTED FILE-----
  Ali: |
    -----BEGIN AGE ENCRYPTED FILE-----
    YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBiY1FCRGIwT0hCbzVQNjFD
    NTNlOWpEUVlMNTJVM0lyZ2RvRXFRRVhSU2lZCjkzaFFQN1VDc1ZMMkJSOGQwOGxP
    SjBoYmQ2bjVQRGQxZEQvcWh6UWxyZFUKLT4gV2EtZ3JlYXNlID5FbjZSICsgWyk1
    P2kKN1Q1V3Z2UWsxZ2VyRnJYWVVTS3lHUVRDNUNDK3psZjBVNFpIOVlURnlscWhE
    RkxITzFzZUU5Y1BuWVVjc2xKSApkWlFqZjlhT2lqQWlqMTJUb1RsU0RNMlZLTjB5
    NnJwSWd3Ci0tLSBsQVFTS1h6TFJEeDZwKytpNUtTTXFpeGxEam1vQkpWQ3VDY0Q3
    UElYN2lRCoVk1wWgE5Yorann/6cWNW6IE44J9Cs+NfxZp287dZArKZXmSFvU+Lxh
    Y2bMC6960PTt9mDYJwEt3MNolwnChwOgN861t5xn+qW9ESlQC2QrU1N5bGqQrIv9
    uo6oAwdYNNmiXQ4rOKKpPrOO+UB2agCmQDBzEw1jOjRlnMSIDj0GhS8PAfwADqhQ
    ifB1DDvMgksAuAE3Ni6Zl8vo7Pvlyy4MJUnT7ifLsRojPaDdlL1Jp8kypK2ZYa24
    oXmJtEMalU1onEwi6kP/EnBL801T2uhyrNiZe8R4y357//A1L5kW4fDUVwztPGHp
    OUltdQxzh9RgBNuQmg2Ar+ZQHCcYBFqI
    -----END AGE ENCRYPTED FILE-----
  Bob: |
    -----BEGIN AGE ENCRYPTED FILE-----
    YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBEbDVmb093SjBReEFDci9k
    MmlQeVU5WFV5ZTNBamM3dG40dDUvdkgvQm53CmhYaklBK3YwYzRjWFJUeU5FOFJq
    TlcwdXZMTkk0UDhvL3hDNllpMkVXYmsKLT4gbVpdWlEqTy1ncmVhc2UgbmV6ICQw
    OmROcmVeICkjRk81QApSdwotLS0gNVJUVEVWdDhlQmJRTVpxV3poZ0ZPUjFpeDg0
    MUw0WGgrMVJpYUZXdWVTcwr/myNyLzZjfFbMJY/oqJ1EVTVPiLpxIwuxV2y8eysl
    O9JFM4MH1b8dUSUT7lBhbPcFjJnG0tS7pbpIPfVY5+qQG2Cz6R8AyVX56i5l2aqm
    eJQw8tVhHyim/UIJMkRaqTa7QTj9+Kzlt9sdStIM3S1bX8JCBMQE/uVkgrePHFz5
    biN1C1MRRZNjh3pKqC8IyzvkkhikPQkC4kQjprZaSgoJ8I5VNUD7J4YiUDLl7hZV
    5ZUuFwTQ+2OEr+lWzMuzoQpCbDDruf/OAkOYbuA6XdsiJpWIirRGakvt9R7lCows
    qq1GhYngPCxrFcXo4NKqKfsdSjqgqQDEixAGd7umOXzd8w==
    -----END AGE ENCRYPTED FILE-----
reason: |
  We needed perform some tests.
  Even with a reason on multiple lines.
expire: 2023-08-27T13:12:00+00:00
"""


def test_cli_recovery_bundle_info_dump_manifest(complete_manifest_recovery_bundle_path):
    runner = CliRunner()
    result = runner.invoke(
        info,
        [
            "--dump-manifest",
            complete_manifest_recovery_bundle_path,
        ],
    )
    assert result.exit_code == 0
    assert result.output == EXPECTED_DUMP_WITH_COMPLETE_MANIFEST


@pytest.fixture
def decryption_key_recovery_tests_bundle_path():
    # Decryption key is:
    # AGE-SECRET-KEY-15PQHAGKV59TFK9TCCWLQZZ7XVV0FADVX5TSCDWVZSEWZ4L2SMARSJAAR0W
    return os.path.join(
        os.path.dirname(__file__),
        "fixtures",
        "decryption-key-recovery.swh-recovery-bundle",
    )


@pytest.fixture
def env_with_deactivated_age_yubikey_plugin_in_path(tmp_path):
    plugin = tmp_path / "age-plugin-yubikey"
    with plugin.open("w") as f:
        f.write("#!/bin/sh\necho Oops! age-yubikey-plugin has been called. >&2\nexit 1")
    plugin.chmod(0o755)
    env = dict(os.environ)
    env["PATH"] = f"{tmp_path}:{env['PATH']}"
    return env


def fake_list_yubikey_identities():
    return [
        ("YubiKey serial 4245067 slot 1", "AGE-PLUGIN-FAKE-ALABASTER"),
        ("YubiKey serial 4245067 slot 2", "AGE-PLUGIN-FAKE-ESSUN"),
        ("YubiKey serial 4245067 slot 3", "AGE-PLUGIN-FAKE-INNON"),
    ]


SHARED_SECRET_ALABASTER = """\
hawk steady behavior leader aunt require decent script simple prayer coastal \
coding story unusual exact lawsuit miracle jury sharp course fraction sprinkle \
various endless hairy company drove evil scroll golden walnut inherit undergo"""
SECRET_KEY_ALABASTER = (
    "AGE-SECRET-KEY-1RQMJJY4XW59F50CNFE5ECA3ZXY64X82HV7Y3E3QJMHSES4NRE9VSE5PFK0"
)

SHARED_SECRET_ESSUN = """\
hawk steady check leader angel camera strike election diploma scared steady \
priest prize often famous crystal quiet teammate parking shaped declare clay \
advance adequate salon invasion regret tackle grumpy heat lips pharmacy story"""
SECRET_KEY_ESSUN = (
    "AGE-SECRET-KEY-10R8AM9Y95ALRN8AFVZR78DEMF2H6UML0DXXM4A3KQ3YX4H0F43HSQN647E"
)

SHARED_SECRET_INNON = """\
hawk steady adequate leader answer patrol hearing hand dismiss squeeze round \
slavery flea manager enjoy species fiber shaped spend news prevent ceramic \
building formal shaped lily raisin pupal harvest jerky mandate subject burning"""
SECRET_KEY_INNON = (
    "AGE-SECRET-KEY-1SRVCJXPYLPJRYW39TVG3PVJNEAXELYZJ0J9335Z0FVUFAU9T79MSU2FNNE"
)

DECRYPTION_KEY_FOR_RECOVERY_TESTS = (
    "AGE-SECRET-KEY-15PQHAGKV59TFK9TCCWLQZZ7XVV0FADVX5TSCDWVZSEWZ4L2SMARSJAAR0W"
)

_original_age_decrypt = age_decrypt


def fake_age_decrypt(secret_key, ciphertext):
    decrypted = {
        "AGE-PLUGIN-FAKE-ALABASTER": SHARED_SECRET_ALABASTER,
        "AGE-PLUGIN-FAKE-ESSUN": SHARED_SECRET_ESSUN,
        "AGE-PLUGIN-FAKE-INNON": SHARED_SECRET_INNON,
    }
    if secret_key in decrypted:
        # We ignore the ciphertext. This should be a controlled test
        # environment.
        return decrypted[secret_key].encode("us-ascii")
    else:
        return _original_age_decrypt(secret_key, ciphertext)


def test_cli_recovery_bundle_recover_decryption_key_from_yubikeys(
    env_with_deactivated_age_yubikey_plugin_in_path,
    mocker,
    decryption_key_recovery_tests_bundle_path,
):
    # We actually don’t want to rely on YubiKeys so let’s do some mocking and hardcoding
    mocker.patch(
        "swh.alter.recovery_bundle.list_yubikey_identities",
        wraps=fake_list_yubikey_identities,
    )
    mocker.patch("swh.alter.recovery_bundle.age_decrypt", wraps=fake_age_decrypt)
    runner = CliRunner()
    result = runner.invoke(
        recover_decryption_key,
        [
            decryption_key_recovery_tests_bundle_path,
        ],
        env=env_with_deactivated_age_yubikey_plugin_in_path,
        catch_exceptions=False,
    )
    assert result.exit_code == 0
    assert DECRYPTION_KEY_FOR_RECOVERY_TESTS in result.output


@pytest.fixture
def alabaster_identity_file_path(tmp_path):
    identity_file = tmp_path / "age-identity-alabaster.txt"
    with identity_file.open("w") as f:
        f.write(SECRET_KEY_ALABASTER + "\n")
    return str(identity_file)


@pytest.fixture
def essun_identity_file_path(tmp_path):
    identity_file = tmp_path / "age-identity-essun.txt"
    with identity_file.open("w") as f:
        f.write(SECRET_KEY_ESSUN + "\n")
    return str(identity_file)


@pytest.fixture
def innon_identity_file_path(tmp_path):
    identity_file = tmp_path / "age-identity-innon.txt"
    with identity_file.open("w") as f:
        f.write(SECRET_KEY_INNON + "\n")
    return str(identity_file)


def test_cli_recovery_bundle_recover_decryption_key_from_identity_files(
    env_with_deactivated_age_yubikey_plugin_in_path,
    decryption_key_recovery_tests_bundle_path,
    alabaster_identity_file_path,
    essun_identity_file_path,
    innon_identity_file_path,
):
    runner = CliRunner()
    result = runner.invoke(
        recover_decryption_key,
        [
            "--identity",
            alabaster_identity_file_path,
            "--identity",
            essun_identity_file_path,
            "--identity",
            innon_identity_file_path,
            decryption_key_recovery_tests_bundle_path,
        ],
        env=env_with_deactivated_age_yubikey_plugin_in_path,
        catch_exceptions=False,
    )
    assert result.exit_code == 0
    assert DECRYPTION_KEY_FOR_RECOVERY_TESTS in result.output


def test_cli_recovery_bundle_recover_decryption_key_from_secrets(
    env_with_deactivated_age_yubikey_plugin_in_path,
    decryption_key_recovery_tests_bundle_path,
):
    runner = CliRunner()
    result = runner.invoke(
        recover_decryption_key,
        [
            "--secret",
            SHARED_SECRET_ALABASTER,
            "--secret",
            SHARED_SECRET_ESSUN,
            "--secret",
            SHARED_SECRET_INNON,
            decryption_key_recovery_tests_bundle_path,
        ],
        env=env_with_deactivated_age_yubikey_plugin_in_path,
        catch_exceptions=False,
    )
    assert result.exit_code == 0
    assert DECRYPTION_KEY_FOR_RECOVERY_TESTS in result.output


def test_cli_recovery_bundle_recover_decryption_key_from_yubikey_and_identity_file_and_secret(
    env_with_deactivated_age_yubikey_plugin_in_path,
    mocker,
    decryption_key_recovery_tests_bundle_path,
    alabaster_identity_file_path,
):
    # We actually don’t want to rely on YubiKeys so let’s do some mocking and hardcoding
    mocker.patch(
        "swh.alter.recovery_bundle.list_yubikey_identities",
        return_value=[("YubiKey serial 4245067 slot 3", "AGE-PLUGIN-FAKE-INNON")],
    )
    mocker.patch("swh.alter.recovery_bundle.age_decrypt", wraps=fake_age_decrypt)
    runner = CliRunner()
    result = runner.invoke(
        recover_decryption_key,
        [
            "--identity",
            alabaster_identity_file_path,
            "--secret",
            SHARED_SECRET_ESSUN,
            # Innon is going to be decrypted using the fake YubiKey
            decryption_key_recovery_tests_bundle_path,
        ],
        env=env_with_deactivated_age_yubikey_plugin_in_path,
        catch_exceptions=False,
    )
    assert result.exit_code == 0
    assert DECRYPTION_KEY_FOR_RECOVERY_TESTS in result.output


def test_cli_recovery_bundle_recover_decryption_key_show_recovered_secrets(
    env_with_deactivated_age_yubikey_plugin_in_path,
    decryption_key_recovery_tests_bundle_path,
    alabaster_identity_file_path,
    essun_identity_file_path,
    innon_identity_file_path,
):
    runner = CliRunner()
    result = runner.invoke(
        recover_decryption_key,
        [
            "--show-recovered-secrets",
            "--identity",
            alabaster_identity_file_path,
            "--identity",
            essun_identity_file_path,
            "--identity",
            innon_identity_file_path,
            decryption_key_recovery_tests_bundle_path,
        ],
        env=env_with_deactivated_age_yubikey_plugin_in_path,
        catch_exceptions=False,
    )
    assert result.exit_code == 0
    assert SHARED_SECRET_ALABASTER in result.output
    assert SHARED_SECRET_ESSUN in result.output
    assert SHARED_SECRET_INNON in result.output


@pytest.fixture
def no_yubikeys_bundle_path():
    # Decryption key is:
    # AGE-SECRET-KEY-15PQHAGKV59TFK9TCCWLQZZ7XVV0FADVX5TSCDWVZSEWZ4L2SMARSJAAR0W
    return os.path.join(
        os.path.dirname(__file__),
        "fixtures",
        "no-yubikeys.swh-recovery-bundle",
    )


def test_cli_recovery_bundle_does_not_always_require_age_plugin_yubikey(
    env_with_deactivated_age_yubikey_plugin_in_path,
    no_yubikeys_bundle_path,
):
    runner = CliRunner()
    result = runner.invoke(
        recover_decryption_key,
        [
            no_yubikeys_bundle_path,
        ],
        env=env_with_deactivated_age_yubikey_plugin_in_path,
        catch_exceptions=False,
    )
    assert result.exit_code != 0
    assert "age-plugin-yubikey" not in result.output
    assert (
        "Unable to decrypt enough shared secrets to recover the object"
        "decryption key."
    )


@pytest.fixture
def rollover_input_proceed_with_rollover():
    return "y\n"


def test_cli_recovery_bundle_rollover_with_decryption_key(
    tmp_path,
    sample_recovery_bundle_path,  # noqa: F811
    remove_config,
    rollover_input_proceed_with_rollover,
):
    bundle_path = shutil.copy(
        sample_recovery_bundle_path, tmp_path / "rollover.swh-recovery-bundle"
    )
    runner = CliRunner()
    result = runner.invoke(
        rollover,
        [
            f"--decryption-key={OBJECT_SECRET_KEY}",
            str(bundle_path),
        ],
        obj={"config": remove_config},
        input=rollover_input_proceed_with_rollover,
        catch_exceptions=False,
    )

    from ..recovery_bundle import RecoveryBundle

    assert result.exit_code == 0
    assert "Shared secrets for test_bundle have been rolled over" in result.output
    bundle = RecoveryBundle(bundle_path)
    assert bundle.share_ids == {"Ali", "Bob", "Camille", "Dlique"}


def test_cli_recovery_bundle_rollover_with_decryption_key_fails_with_wrong_key(
    tmp_path,
    sample_recovery_bundle_path,  # noqa: F811
    remove_config,
    rollover_input_proceed_with_rollover,
):
    bundle_path = shutil.copy(
        sample_recovery_bundle_path, tmp_path / "rollover.swh-recovery-bundle"
    )
    runner = CliRunner()
    result = runner.invoke(
        rollover,
        [
            "--decryption-key=AGE-SECRET-KEY-1SPTRNLVZYFGVFZ2ZXVUKSEZ6MRP2HNJFCJZGXL8Q3JMA3CJZXPFS9Y7LSD",
            str(bundle_path),
        ],
        obj={"config": remove_config},
        input=rollover_input_proceed_with_rollover,
        catch_exceptions=False,
    )
    assert result.exit_code != 0
    assert "Wrong decryption key for this bundle (test_bundle)" in result.output


def test_cli_recovery_bundle_rollover_with_identity_files(
    tmp_path,
    decryption_key_recovery_tests_bundle_path,
    remove_config,
    alabaster_identity_file_path,
    essun_identity_file_path,
    innon_identity_file_path,
    rollover_input_proceed_with_rollover,
):
    bundle1_path = shutil.copy(
        decryption_key_recovery_tests_bundle_path,
        tmp_path / "rollover1.swh-recovery-bundle",
    )
    bundle2_path = shutil.copy(
        decryption_key_recovery_tests_bundle_path,
        tmp_path / "rollover2.swh-recovery-bundle",
    )
    runner = CliRunner()
    result = runner.invoke(
        rollover,
        [
            "--identity",
            innon_identity_file_path,
            "--identity",
            alabaster_identity_file_path,
            "--identity",
            essun_identity_file_path,
            str(bundle1_path),
            str(bundle2_path),
        ],
        obj={"config": remove_config},
        input=rollover_input_proceed_with_rollover,
        catch_exceptions=False,
    )
    assert result.exit_code == 0

    from ..recovery_bundle import RecoveryBundle

    bundle1 = RecoveryBundle(bundle1_path)
    assert bundle1.share_ids == {"Ali", "Bob", "Camille", "Dlique"}
    bundle2 = RecoveryBundle(bundle2_path)
    assert bundle2.share_ids == {"Ali", "Bob", "Camille", "Dlique"}


def test_cli_recovery_bundle_rollover_can_be_canceled(
    tmp_path, sample_recovery_bundle_path, remove_config  # noqa: F811
):
    bundle_path = shutil.copy(
        sample_recovery_bundle_path, tmp_path / "rollover.swh-recovery-bundle"
    )
    runner = CliRunner()
    result = runner.invoke(
        rollover,
        [
            f"--decryption-key={OBJECT_SECRET_KEY}",
            str(bundle_path),
        ],
        obj={"config": remove_config},
        input="n\n",
        catch_exceptions=False,
    )
    assert result.exit_code != 0
    assert "Aborted" in result.output
