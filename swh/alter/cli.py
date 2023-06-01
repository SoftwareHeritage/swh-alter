import hashlib
import logging
from typing import List

import click

from swh.core.cli import CONTEXT_SETTINGS
from swh.core.cli import swh as swh_cli_group
from swh.model.swhids import ExtendedSWHID

from .inventory import make_inventory
from .removable import mark_removable

logger = logging.getLogger(__name__)


class SwhidOrUrlParamType(click.ParamType):
    name = "swhid or origin URL"

    def convert(self, value, param, ctx):
        from swh.model.exceptions import ValidationError
        from swh.model.swhids import ExtendedSWHID

        if value.startswith("swh:1:"):
            try:
                return ExtendedSWHID.from_string(value)
            except ValidationError:
                self.fail(f"expected extended SWHID, got {value!r}", param, ctx)
        else:
            sha1 = hashlib.sha1(value.encode("utf-8")).hexdigest()
            swhid = ExtendedSWHID.from_string(f"swh:1:ori:{sha1}")
            logger.info(
                "Assuming “%s” is an origin URL; computed origin swhid: %s",
                value,
                swhid,
            )
            return swhid


DEFAULT_CONFIG = {
    "storage": {
        "cls": "postgresql",
        "db": "dbname=softwareheritage host=db.internal.softwareheritage.org user=guest",
        "objstorage": {
            "cls": "memory",
        },
    },
    "graph_client": {
        "url": "http://granet.internal.softwareheritage.org:5009",
        # timeout is in seconds
        # see https://requests.readthedocs.io/en/latest/user/advanced/#timeouts
        "timeout": 10,
    },
}


@swh_cli_group.group(name="alter", context_settings=CONTEXT_SETTINGS)
@click.pass_context
def alter_cli_group(ctx):
    """Archive alteration tools.

    Location of the configuration should be specified through the environment
    variable ``SWH_CONFIG_FILENAME``.

    Expected config format:

        \b
        storage:
          cls: postgresql
          db: "service=…"
          objstorage:
            cls: memory
        \b
        graph:
          cls: remote
          url: "http://granet.internal.softwareheritage.org:5009"
    """
    from swh.core import config

    conf = config.load_from_envvar(default_config=DEFAULT_CONFIG)
    ctx.ensure_object(dict)
    ctx.obj["config"] = conf
    return ctx


@alter_cli_group.command()
@click.option(
    "--dry-run", is_flag=True, help="perform a trial run with no changes made"
)
@click.option(
    "--output-inventory-subgraph",
    type=click.File(mode="w", atomic=True),
)
@click.option(
    "--output-removable-subgraph",
    type=click.File(mode="w", atomic=True),
)
@click.option(
    "--output-pruned-removable-subgraph",
    type=click.File(mode="w", atomic=True),
)
@click.argument(
    "swhids",
    metavar="<SWHID|URL>..",
    type=SwhidOrUrlParamType(),
    required=True,
    nargs=-1,
)
@click.pass_obj
def remove(
    obj,
    swhids: List[ExtendedSWHID],
    dry_run: bool,
    output_inventory_subgraph,
    output_removable_subgraph,
    output_pruned_removable_subgraph,
):
    """Remove the given SWHIDs or URLs from the archive."""
    conf = obj["config"]
    from swh.storage import get_storage

    storage = get_storage(**conf["storage"])
    from swh.graph.http_client import RemoteGraphClient

    graph_client = RemoteGraphClient(**conf["graph_client"])

    click.echo("Removing the following origins:")
    for swhid in swhids:
        click.echo(f" - {swhid}")
    inventory_subgraph = make_inventory(storage, graph_client, swhids)
    if output_inventory_subgraph:
        inventory_subgraph.write_dot(output_inventory_subgraph)
        output_inventory_subgraph.close()
    removable_subgraph = mark_removable(storage, graph_client, inventory_subgraph)
    if output_removable_subgraph:
        removable_subgraph.write_dot(output_removable_subgraph)
        output_removable_subgraph.close()
    removable_subgraph.delete_unremovable()
    if output_pruned_removable_subgraph:
        removable_subgraph.write_dot(output_pruned_removable_subgraph)
        output_pruned_removable_subgraph.close()
    if dry_run:
        removable_swhids = list(removable_subgraph.removable_swhids())
        click.echo(f"We would remove {len(removable_swhids)} objects:")
        for swhid in removable_swhids:
            click.echo(f" - {swhid}")
        return
    raise NotImplementedError("Actual removal still need to be written")
