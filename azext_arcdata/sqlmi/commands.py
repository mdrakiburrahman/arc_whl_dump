# ------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# ------------------------------------------------------------------------------

from azure.cli.core.commands import CliCommandType
from azext_arcdata.sqlmi.client import beget, beget_no_namespace


def load_commands(self, _):
    operations = CliCommandType(operations_tmpl="azext_arcdata.sqlmi.custom#{}")

    with self.command_group(
        "sql mi-arc", operations, client_factory=beget
    ) as g:
        g.command("create", "arc_sql_mi_create")
        g.command("delete", "arc_sql_mi_delete")
        # pylint: disable=E5001
        g.command("show", "arc_sql_mi_show")
        g.command("get-mirroring-cert", "arc_sql_mi_getmirroringcert")
        g.command("list", "arc_sql_mi_list")
        g.command("edit", "arc_sql_mi_edit")

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
        "sql mi-arc dag", operations, client_factory=beget, is_preview=True
    ) as g:
        g.command("create", "arc_sql_mi_dag_create")
        g.command("delete", "arc_sql_mi_dag_delete")
        g.command("get", "arc_sql_mi_dag_get")
