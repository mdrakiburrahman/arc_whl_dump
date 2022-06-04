# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

# pylint: disable=line-too-long
from ._format import customlocation_show_table_format
from ._format import customlocation_list_table_format


def load_command_table(self, _):

    with self.command_group('customlocation') as g:
        g.custom_command('create', 'create_customlocation')
        g.custom_show_command('show', 'get_customlocation', table_transformer=customlocation_show_table_format)
        g.custom_command('delete', 'delete_customlocation', confirmation=True)
        g.custom_command('list', 'list_customlocation', table_transformer=customlocation_list_table_format)
        g.custom_command('list-enabled-resource-types', 'list_enabled_resource_types_customlocation')
        g.custom_command('update', 'update_customlocation')
        g.custom_command('patch', 'patch_customlocation')
