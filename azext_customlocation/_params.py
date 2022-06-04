# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------
# pylint: disable=line-too-long

from knack.arguments import CLIArgumentType
from azure.cli.core.commands.parameters import (
    tags_type
)
from azure.cli.core.commands.validators import get_default_location_from_resource_group


def load_arguments(self, _):
    customlocations_name_type = CLIArgumentType(options_list=['--name', '-n'], help='Name of the Customlocation.', id_part=None)

    with self.argument_context('customlocation') as c:
        c.argument('cl_name', customlocations_name_type)
        c.argument('namespace', help='Namespace for Custom Location. For namespace-scoped extensions, this should match namespace associated with the cluster extension operator.', options_list=["--namespace"])
        c.argument('location', validator=get_default_location_from_resource_group)
        c.argument('host_resource_id', options_list=['--host-resource-id'], help='Host resource ID of the connected cluster.')
        c.argument('cluster_extension_ids', nargs='*', options_list=['--cluster-extension-ids', '-c'], help='Space-seperated list of the cluster extension ids - input full id in the format /subscription/.../resourceGroups/.../Microsoft.Kubernetes/connectedClusters/.../providers/Microsoft.KubernetesConfiguration/extensions/...')
        c.argument('tags', tags_type)
        c.argument('assign_identity', options_list=['--assign-identity'], help='Create CustomLocation resource with "SystemAssigned" or "None" type identity.')

    with self.argument_context('customlocation update') as c:
        c.argument('location', help='Location of Custom Location resource', options_list=["--location", "-l"])

    with self.argument_context('customlocation create') as c:
        c.argument('kubeconfig', options_list=['--kubeconfig', '-k'], help='Admin Kubeconfig of Cluster. Needs to passed in as a file if the cluster is a non-AAD enabled Cluster.')

    with self.argument_context('customlocation patch') as c:
        c.argument('display_name', options_list=['--display-name', '-d'], help='Display Name of Custom Location.')
