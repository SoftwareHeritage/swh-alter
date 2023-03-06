# Copyright (C) 2023 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import shutil
import subprocess

from click.testing import CliRunner
import pytest

from ..cli import DEFAULT_CONFIG, remove
from .test_inventory import (  # noqa
    directory_6_with_multiple_entries_pointing_to_the_same_content,
    snapshot_20_with_multiple_branches_pointing_to_the_same_head,
)
from .test_inventory import graph_client_with_only_initial_origin  # noqa: F401
from .test_inventory import origin_with_submodule  # noqa: F401
from .test_inventory import sample_populated_storage  # noqa: F401
from .test_removable import inventory_from_forked_origin  # noqa: F401
from .test_removable import storage_with_references_from_forked_origin  # noqa: F401


@pytest.fixture
def mocked_external_resources(
    mocker,
    graph_client_with_only_initial_origin,  # noqa: F811
    storage_with_references_from_forked_origin,  # noqa: F811
):
    mocker.patch(
        "swh.storage.get_storage",
        return_value=storage_with_references_from_forked_origin,
    )
    mocker.patch(
        "swh.graph.http_client.RemoteGraphClient",
        return_value=graph_client_with_only_initial_origin,
    )


def test_remove_dry_run_with_origin_as_swhid(mocked_external_resources):
    runner = CliRunner()
    result = runner.invoke(
        remove,
        ["--dry-run", "swh:1:ori:8f50d3f60eae370ddbf85c86219c55108a350165"],
        obj={"config": DEFAULT_CONFIG},
    )
    assert result.exit_code == 0
    assert "We would remove 11 objects" in result.output


def test_remove_dry_run_with_origin_as_url(mocked_external_resources):
    runner = CliRunner()
    result = runner.invoke(
        remove,
        ["--dry-run", "https://example.com/swh/graph2"],
        obj={"config": DEFAULT_CONFIG},
    )
    assert result.exit_code == 0
    assert "We would remove 11 objects" in result.output


def test_remove_dry_run_with_multiple_origins(mocked_external_resources):
    runner = CliRunner()
    result = runner.invoke(
        remove,
        [
            "--dry-run",
            "https://example.com/swh/graph",
            "swh:1:ori:8f50d3f60eae370ddbf85c86219c55108a350165",
        ],
        obj={"config": DEFAULT_CONFIG},
    )
    assert result.exit_code == 0
    assert "We would remove 23 objects" in result.output


@pytest.mark.skipif(
    not shutil.which("gc"), reason="missing `gc` executable from graphviz"
)
def test_remove_output_inventory_subgraph(mocked_external_resources):
    runner = CliRunner()
    with runner.isolated_filesystem():
        runner.invoke(
            remove,
            [
                "--dry-run",
                "--output-inventory-subgraph=subgraph.dot",
                "swh:1:ori:8f50d3f60eae370ddbf85c86219c55108a350165",
            ],
            obj={"config": DEFAULT_CONFIG},
        )
        completed_process = subprocess.run(
            ["gc", "subgraph.dot"], check=True, capture_output=True
        )
        assert b"      21      24 Inventory" in completed_process.stdout


@pytest.mark.skipif(
    not shutil.which("gc"), reason="missing `gc` executable from graphviz"
)
def test_remove_output_removable_subgraph(mocked_external_resources):
    runner = CliRunner()
    with runner.isolated_filesystem():
        runner.invoke(
            remove,
            [
                "--dry-run",
                "--output-removable-subgraph=subgraph.dot",
                "swh:1:ori:8f50d3f60eae370ddbf85c86219c55108a350165",
            ],
            obj={"config": DEFAULT_CONFIG},
        )
        completed_process = subprocess.run(
            ["gc", "subgraph.dot"], check=True, capture_output=True
        )
        assert b"      21      24 Removable" in completed_process.stdout


@pytest.mark.skipif(
    not shutil.which("gc"), reason="missing `gc` executable from graphviz"
)
def test_remove_output_pruned_removable_subgraph(mocked_external_resources):
    runner = CliRunner()
    with runner.isolated_filesystem():
        runner.invoke(
            remove,
            [
                "--dry-run",
                "--output-pruned-removable-subgraph=subgraph.dot",
                "swh:1:ori:8f50d3f60eae370ddbf85c86219c55108a350165",
            ],
            obj={"config": DEFAULT_CONFIG},
        )
        completed_process = subprocess.run(
            ["gc", "subgraph.dot"], check=True, capture_output=True
        )
        assert b"      11      10 Removable" in completed_process.stdout
