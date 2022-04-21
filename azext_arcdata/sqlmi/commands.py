# ------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# ------------------------------------------------------------------------------

from azure.cli.core.commands import CliCommandType
from azext_arcdata.sqlmi.client import beget, beget_no_namespace
import azext_arcdata.sqlmi.validators as validators


def load_commands(self, _):
    operations = CliCommandType(operations_tmpl="azext_arcdata.sqlmi.custom#{}")

    with self.command_group(
        "sql mi-arc", operations, client_factory=beget
    ) as g:
        g.command(
            "create",
            "arc_sql_mi_create",
            supports_no_wait=True,
            validator=validators.validate_create,
        )
        g.command(
            "upgrade",
            "arc_sql_mi_upgrade",
            supports_no_wait=True,
            validator=validators.validate_upgrade,
        )

        g.command(
            "delete",
            "arc_sql_mi_delete",
            supports_no_wait=True,
            validator=validators.validate_delete,
        )
        g.show_command(
            "show", "arc_sql_mi_show", validator=validators.validate_show
        )
        g.command("get-mirroring-cert", "arc_sql_mi_getmirroringcert")
        g.command("list", "arc_sql_mi_list", validator=validators.validate_list)
        g.command(
            "update",
            "arc_sql_mi_update",
            supports_no_wait=True,
            validator=validators.validate_update,
        )

        g.command(
            "edit",
            "arc_sql_mi_edit",
            deprecate_info=g.deprecate(
                target="edit", redirect="update", hide=True
            ),
            validator=validators.validate_update,
        )

    with self.command_group(
        "sql mi-arc endpoint", operations, client_factory=beget
    ) as g:
        g.command("list", "arc_sql_endpoint_list")

    with self.command_group(
        "sql mi-arc config", operations, client_factory=beget_no_namespace
    ) as g:
        g.command("init", "arc_sql_mi_config_init")
        g.command("patch", "arc_sql_mi_config_patch")
        g.command("add", "arc_sql_mi_config_add")
        g.command("replace", "arc_sql_mi_config_replace")
        g.command("remove", "arc_sql_mi_config_remove")

    with self.command_group(
        "sql instance-failover-group-arc", operations, client_factory=beget
    ) as g:
        g.command("create", "arc_sql_mi_fog_create")
        g.command("update", "arc_sql_mi_fog_update")
        g.command("delete", "arc_sql_mi_fog_delete")
        g.show_command("show", "arc_sql_mi_fog_show")

    with self.command_group("sql instance-failover-group-arc", is_preview=True):
        pass
