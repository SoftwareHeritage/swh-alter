import click

from swh.core.cli import CONTEXT_SETTINGS
from swh.core.cli import swh as swh_cli_group


@swh_cli_group.group(name="foo", context_settings=CONTEXT_SETTINGS)
@click.pass_context
def foo_cli_group(ctx):
    """Foo main command."""


@foo_cli_group.command()
@click.option("--bar", help="Something")
@click.pass_context
def bar(ctx, bar):
    """Do something."""
    click.echo("bar")
