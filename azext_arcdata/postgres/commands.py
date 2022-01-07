# ------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# -----------------------------------------------------------------------------

from azure.cli.core.commands import CliCommandType
from azext_arcdata.postgres.client import beget


def load_commands(self, _):
    operations = CliCommandType(
        operations_tmpl="azext_arcdata.postgres.custom#{}"
    )
    # --------------------------------------------------------------------------
    # Server Commands
    # --------------------------------------------------------------------------
    with self.command_group(
        "postgres arc-server", operations, client_factory=beget
    ) as g:
        g.command("create", "postgres_server_arc_create")
        g.command("delete", "postgres_server_arc_delete")
        # pylint: disable=E5001
        g.command("show", "postgres_server_arc_show")
        g.command(
            "list", "postgres_server_arc_list"
        )
        g.command("edit", "postgres_server_arc_edit")

    # with self.command_group('postgres arc-server config',
    #                operations, client_factory=beget) as g:
    #     g.command('init', 'postgres_server_arc_config_init')

    # with self.command_group('postgres arc-server config',
    #                 operations, client_factory=beget) as g:
    #     g.command('patch', 'postgres_server_arc_config_patch')
    #     g.command('add', 'postgres_server_arc_config_add')
    #     g.command('replace', 'postgres_server_arc_config_replace')
    #     g.command('remove', 'postgres_server_arc_config_remove')

    # --------------------------------------------------------------------------
    # Endpoint Commands
    # --------------------------------------------------------------------------
    with self.command_group(
        "postgres arc-server endpoint",
        operations,
        client_factory=beget,
        # TODO: this command was executed with beget_no_auth in azdata
    ) as g:
        g.command(
            "list", "arc_postgres_endpoint_list"
        )

    with self.command_group("postgres arc-server", is_preview=True):
        pass
