from click.testing import CliRunner
import pytest
import yaml

from swh.alter.cli import list_candidates, remove
from swh.alter.notifications import RemovalNotification

from .test_cli import (
    DEFAULT_CONFIG,
    TWO_GROUPS_REQUIRED_WITH_ONE_MINIMUM_SHARE_EACH_SECRET_SHARING_YAML,
)


@pytest.fixture
def remove_config(kafka_server, kafka_prefix):
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
            "allow_delete": True,
        },
    }
    config["removal_journals"] = {
        "example": {
            "cls": "kafka",
            "brokers": [
                kafka_server,
            ],
            "prefix": kafka_prefix,
            "client_id": "swh.alter.removals",
        },
    }
    config["recovery_bundles"] = yaml.safe_load(
        TWO_GROUPS_REQUIRED_WITH_ONE_MINIMUM_SHARE_EACH_SECRET_SHARING_YAML
    )
    config["journal_writer"] = {
        "cls": "memory",
    }
    return config


@pytest.fixture
def journal_writer_for_notifications(mocker):
    from swh.journal.writer import get_journal_writer

    writer = get_journal_writer(cls="memory")

    def _get_journal_writer(cls, **kw):
        if cls == "memory":
            return writer
        return get_journal_writer(cls, **kw)

    mocker.patch(
        "swh.journal.writer.get_journal_writer",
        _get_journal_writer,
    )
    return writer


@pytest.fixture
def hijack_content_from_data(mocker):
    from swh.model.model import Content

    def from_data(cls, data, status="visible", ctime=None):
        value = int.from_bytes(data)
        return Content.from_dict(
            {
                "sha1": bytes.fromhex(f"{value:040x}"),
                "sha1_git": bytes.fromhex(f"{value:040x}"),
                "sha256": bytes.fromhex(f"{value:064x}"),
                "blake2s256": bytes.fromhex(f"{value:064x}"),
                "data": bytes.fromhex(f"{value:02x}"),
                "length": 1,
                "status": status,
                "ctime": ctime,
            }
        )

    mocker.patch("swh.model.model.Content.from_data", from_data)


def test_cli_remove_journal_notify(
    mocked_external_resources,
    remove_config,
    journal_writer_for_notifications,
    tmp_path,
    hijack_content_from_data,
):
    origin = "swh:1:ori:8f50d3f60eae370ddbf85c86219c55108a350165"
    expected_swhids = {
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
    runner = CliRunner(mix_stderr=False)
    result = runner.invoke(
        list_candidates,
        [origin],
        obj={"config": remove_config},
        catch_exceptions=False,
    )
    assert result.exit_code == 0
    assert set(result.stdout.splitlines()) == expected_swhids

    result = runner.invoke(
        remove,
        [
            "--identifier",
            "this-is-not-my-departement",
            "--recovery-bundle",
            tmp_path / "test.swh-recovery-bundle",
            "--output-inventory-subgraph",
            tmp_path / "test.inventory-subpgraph",
            "--output-removable-subgraph",
            tmp_path / "test.removable-subpgraph",
            "--output-pruned-removable-subgraph",
            tmp_path / "test.pruned-removable-subpgraph",
            origin,
        ],
        input="y\n",
        obj={"config": remove_config},
        catch_exceptions=False,
    )

    objects = journal_writer_for_notifications.objects
    assert len(objects) == 1
    obj_type, notif = objects[0]
    assert obj_type == "removal_notification"
    assert isinstance(notif, RemovalNotification)
    assert notif.removal_identifier == "this-is-not-my-departement"
    assert notif.reason is None
    assert str(notif.requested[0]) == origin
    assert {str(swhid) for swhid in notif.removed_objects} == expected_swhids
