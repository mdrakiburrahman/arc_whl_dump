# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------
# pylint: disable=unused-import

from azure.cli.core import AzCommandsLoader
from azure.cli.core.commands import CliCommandType
from azext_customlocation._client_factory import cf_customlocations
from azext_customlocation._help import helps
from azext_customlocation.commands import load_command_table
from azext_customlocation._params import load_arguments


class CustomlocationsCommandsLoader(AzCommandsLoader):

    def __init__(self, cli_ctx=None):
        customlocations_custom = CliCommandType(
            operations_tmpl='azext_customlocation.custom#{}',
            client_factory=cf_customlocations)
        super(CustomlocationsCommandsLoader, self).__init__(cli_ctx=cli_ctx, custom_command_type=customlocations_custom)

    def load_command_table(self, args):
        load_command_table(self, args)
        return self.command_table

    def load_arguments(self, command):
        load_arguments(self, command)


COMMAND_LOADER_CLS = CustomlocationsCommandsLoader
