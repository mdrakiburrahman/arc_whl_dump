# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

from azure.cli.core.commands.client_factory import get_mgmt_service_client
from azext_customlocation.vendored_sdks.azure.mgmt.extendedlocation import v2021_08_15


def cf_customlocations(cli_ctx, *_):
    return get_mgmt_service_client(cli_ctx, v2021_08_15.CustomLocations)
