# ------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# ------------------------------------------------------------------------------

from azext_arcdata.dc.client import beget, beget_no_namespace

from azext_arcdata.dc.validators import validate_copy_logs

# from knack.output import format_table
from azure.cli.core.commands import CliCommandType


def load_commands(self, _):
    operations = CliCommandType(operations_tmpl="azext_arcdata.dc.custom#{}")

    with self.command_group(
        "arcdata dc", operations, client_factory=beget_no_namespace
    ) as g:
        g.command("endpoint list", "dc_endpoint_list")  # , output=format_table)
        g.command("upload", "dc_upload")

    with self.command_group(
        "arcdata dc", operations, client_factory=beget
    ) as g:
        g.command("create", "dc_create")
        g.command("config show", "dc_config_show")
        g.command("status show", "dc_status_show")
        g.command("delete", "dc_delete")
        g.command("export", "dc_export")

    with self.command_group(
        "arcdata dc config", operations, client_factory=beget_no_namespace
    ) as g:
        g.command("list", "dc_config_list")
        g.command("init", "dc_config_init")
        g.command("patch", "dc_config_patch")
        g.command("add", "dc_config_add")
        g.command("replace", "dc_config_replace")
        g.command("remove", "dc_config_remove")

    with self.command_group(
        "arcdata dc debug", operations, client_factory=beget
    ) as g:
        g.command(
            "copy-logs", "dc_debug_copy_logs", validator=validate_copy_logs
        )
        # TODO: g.command("dump", "dc_debug_dump")

    with self.command_group(
        "arcdata", operations, client_factory=beget_no_namespace
    ) as g:
        g.command("resource-kind list", "arc_resource_kind_list")
        g.command("resource-kind get", "arc_resource_kind_get")
