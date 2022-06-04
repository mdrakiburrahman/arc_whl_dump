# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

import base64
from knack.util import CLIError
# Resource Creation
from azure.cli.core.util import sdk_no_wait
from azure.cli.core.profiles import ResourceType
from azure.cli.core.commands.client_factory import get_mgmt_service_client
from azext_customlocation.vendored_sdks.azure.mgmt.extendedlocation import v2021_08_15
import azext_customlocation.helper as helper

# pylint:disable=inconsistent-return-statements
# pylint:disable=line-too-long


def create_customlocation(cmd, resource_group_name, cl_name, cluster_extension_ids, namespace,
                          host_resource_id, kubeconfig=None, location=None, tags=None, assign_identity=None, no_wait=False):
    # Validate that subscription is registered for Custom Locations
    try:
        helper.validate_cli_resource_type(
            cmd.cli_ctx, ResourceType.MGMT_RESOURCE_RESOURCES)
    except CLIError as e:
        print(e)
        return

    # Get CustomLocations Client
    cl_client = get_mgmt_service_client(
        cmd.cli_ctx, v2021_08_15.CustomLocations)

    # Check if the Kubeconfig is passed in
    # Object to pass in authentication
    cl_auth = v2021_08_15.models.CustomLocationPropertiesAuthentication()
    if kubeconfig is None:
        cl_auth = None
    else:
        # open the file
        try:
            with open(kubeconfig, 'r') as stream:
                # Parse config file into necessary components.
                kubeconfig_value = stream.read()
                message_bytes = kubeconfig_value.encode('ascii')
                base64_bytes = base64.b64encode(message_bytes)
                base64_kubeconfig = base64_bytes.decode('ascii')
                cl_auth.value = base64_kubeconfig
        except FileNotFoundError as e:
            print("File Not Found", e)

    cl_host_type = v2021_08_15.models.HostType("Kubernetes")

    helper.validate_ce_ids(cluster_extension_ids)
    host_resource_id = host_resource_id.strip()
    identity = helper.validate_identity_param(assign_identity)

    # parameters
    customlocation = v2021_08_15.models.CustomLocation(
        host_type=cl_host_type.kubernetes,
        location=location,
        display_name=cl_name,
        namespace=namespace,
        cluster_extension_ids=cluster_extension_ids,
        host_resource_id=host_resource_id,
        authentication=cl_auth,
        tags=tags,
        identity=identity
    )

    return sdk_no_wait(no_wait, cl_client.create_or_update, resource_group_name=resource_group_name,
                       resource_name=cl_name, parameters=customlocation)


def patch_customlocation(cmd, resource_group_name, cl_name, namespace=None,
                         host_resource_id=None, cluster_extension_ids=None, display_name=None, tags=None, location=None, assign_identity=None, no_wait=False):
    # Validate that subscription is registered for Custom Locations
    try:
        helper.validate_cli_resource_type(
            cmd.cli_ctx, ResourceType.MGMT_RESOURCE_RESOURCES)
    except CLIError as e:
        print(e)
        return

    # Get CustomLocation Client
    cl_client = get_mgmt_service_client(
        cmd.cli_ctx, v2021_08_15.CustomLocations)

    helper.validate_ce_ids(cluster_extension_ids)

    if host_resource_id is not None:
        host_resource_id = host_resource_id.strip()

    identity = helper.validate_identity_param(assign_identity)

    # Variables are wrapped in PatchableCustomLocations model in update() operation
    return sdk_no_wait(no_wait, cl_client.update, resource_group_name=resource_group_name, resource_name=cl_name,
                       location=location,
                       namespace=namespace,
                       display_name=display_name,
                       cluster_extension_ids=cluster_extension_ids,
                       host_resource_id=host_resource_id,
                       tags=tags, identity=identity)


def update_customlocation(cmd, resource_group_name, cl_name, cluster_extension_ids, namespace,
                          host_resource_id, location=None, tags=None, assign_identity=None, no_wait=False):
    # Validate that subscription is registered for Custom Locations
    try:
        helper.validate_cli_resource_type(
            cmd.cli_ctx, ResourceType.MGMT_RESOURCE_RESOURCES)
    except CLIError as e:
        print(e)
        return

    # Get CustomLocation Client
    cl_client = get_mgmt_service_client(
        cmd.cli_ctx, v2021_08_15.CustomLocations)

    helper.validate_ce_ids(cluster_extension_ids)
    host_resource_id = host_resource_id.strip()

    identity = helper.validate_identity_param(assign_identity)

    # parameters
    customlocation = v2021_08_15.models.CustomLocation(
        location=location,
        namespace=namespace,
        display_name=cl_name,
        cluster_extension_ids=cluster_extension_ids,
        host_resource_id=host_resource_id,
        tags=tags,
        identity=identity
    )
    return sdk_no_wait(no_wait, cl_client.create_or_update, resource_group_name=resource_group_name,
                       resource_name=cl_name, parameters=customlocation)


def get_customlocation(cmd, resource_group_name, cl_name):
    # Get CustomLocations Client
    cl_client = get_mgmt_service_client(
        cmd.cli_ctx, v2021_08_15.CustomLocations)
    return cl_client.get(resource_group_name=resource_group_name, resource_name=cl_name)


def list_customlocation(cmd, resource_group_name=None):
    # Get CustomLocations Client
    cl_client = get_mgmt_service_client(
        cmd.cli_ctx, v2021_08_15.CustomLocations)

    if resource_group_name is None:
        return cl_client.list_by_subscription()
    return cl_client.list_by_resource_group(resource_group_name=resource_group_name)


def list_enabled_resource_types_customlocation(cmd, resource_group_name, cl_name):
    # Get CustomLocation Client
    cl_client = get_mgmt_service_client(
        cmd.cli_ctx, v2021_08_15.CustomLocations)
    return cl_client.list_enabled_resource_types(resource_group_name=resource_group_name, resource_name=cl_name)


def delete_customlocation(cmd, resource_group_name, cl_name, no_wait=False):
    # Validate that subscription is registered for Custom Locations
    try:
        helper.validate_cli_resource_type(
            cmd.cli_ctx, ResourceType.MGMT_RESOURCE_RESOURCES)
    except CLIError as e:
        print(e)
        return

    # Get CustomLocation Client
    cl_client = get_mgmt_service_client(
        cmd.cli_ctx, v2021_08_15.CustomLocations)
    return sdk_no_wait(no_wait, cl_client.delete, resource_group_name=resource_group_name, resource_name=cl_name)
