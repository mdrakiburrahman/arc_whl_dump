# ------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# ------------------------------------------------------------------------------

"""Command definitions for `data control`."""
import uuid
from azext_arcdata.dc.azure.constants import (
    API_VERSION,
    INSTANCE_TYPE_DATA_CONTROLLER,
    MONITORING_METRICS_PUBLISHER_ROLE_ID,
    RESOURCE_PROVIDER_NAMESPACE,
    ROLE_DESCRIPTIONS,
)
from azure.cli.core.azclierror import ValidationError
from azext_arcdata.dc.constants import LAST_USAGE_UPLOAD_FLAG
from azext_arcdata.dc.export_util import (
    ExportType,
    logs_upload,
    metrics_upload,
    _get_log_workspace_credentials_from_env,
    EXPORT_DATA_JSON_SCHEMA,
    EXPORT_FILE_DICT_KEY,
    EXPORT_SANITIZERS,
    get_export_timestamp_from_file,
    check_prompt_export_output_file,
    set_azure_upload_status,
    update_upload_status_file,
    update_azure_upload_status,
)
from azext_arcdata.core.serialization import Sanitizer
from azext_arcdata.core.prompt import (
    prompt_for_input,
    prompt_for_choice,
    prompt_assert,
    prompt_y_n,
)
from azext_arcdata.core.arcdata_cli_credentials import ArcDataCliCredential
from azext_arcdata.core.util import DeploymentConfigUtil
from jsonschema import validate
from knack.prompting import NoTTYException
from knack.log import get_logger
from knack.cli import CLIError
from colorama import Fore

import json
import os
from msrestazure.tools import is_valid_resource_id
import yaml
import shutil

logger = get_logger(__name__)


def dc_create(
    client,
    name,
    connectivity_mode,
    resource_group,
    location,
    profile_name=None,
    path=None,
    storage_class=None,
    infrastructure=None,
    labels=None,
    annotations=None,
    service_annotations=None,
    service_labels=None,
    storage_labels=None,
    storage_annotations=None,
    no_wait=False,
    # -- direct --
    custom_location=None,
    auto_upload_metrics=None,
    auto_upload_logs=None,
    # -- indirect --
    namespace=None,
    logs_ui_public_key_file=None,
    logs_ui_private_key_file=None,
    metrics_ui_public_key_file=None,
    metrics_ui_private_key_file=None,
    use_k8s=None,
):
    try:
        stdout = client.stdout
        if not path and not profile_name:
            from azext_arcdata.kubernetes_sdk.dc.constants import CONFIG_DIR

            # Prompt the user for a choice between configs
            stdout("Please choose a deployment configuration: ")
            stdout(
                "To see more information please exit and use command:\n "
                "az arcdata dc config list -c <config_profile>"
            )

            config_dir = client.services.dc.get_deployment_config_dir()
            choices = client.services.dc.list_configs()
            profile = prompt_for_choice(choices, default=choices[7]).lower()
            path = os.path.join(config_dir, profile)
            logger.debug("Profile path: %s", path)

        # -- Apply Subscription --
        subscription = client.subscription or prompt_assert("Subscription: ")
        stdout("\nUsing subscription '{}'.\n".format(subscription))

        # -- Apply Configuration Directory --
        cvo = client.args_to_command_value_object(
            {
                "name": name,
                "connectivity_mode": connectivity_mode,
                "resource_group": resource_group,
                "location": location,
                "profile_name": profile_name,
                "path": path,
                "storage_class": storage_class,
                "infrastructure": infrastructure,
                "labels": labels,
                "annotations": annotations,
                "service_annotations": service_annotations,
                "service_labels": service_labels,
                "storage_labels": storage_labels,
                "storage_annotations": storage_annotations,
                "logs_ui_public_key_file": logs_ui_public_key_file,
                "logs_ui_private_key_file": logs_ui_private_key_file,
                "metrics_ui_public_key_file": metrics_ui_public_key_file,
                "metrics_ui_private_key_file": metrics_ui_private_key_file,
                "subscription": subscription,
                "custom_location": custom_location,
                "auto_upload_metrics": auto_upload_metrics,
                "auto_upload_logs": auto_upload_logs,
                "namespace": namespace,
                "no_wait": no_wait,
            }
        )

        return client.services.dc.create(cvo)

    except (NoTTYException, ValueError, Exception) as e:
        raise CLIError(e)


def dc_update(
    client,
    name,
    resource_group_name,
    auto_upload_logs=None,
    auto_upload_metrics=None,
):
    """
    Update data controller properties.
    """

    # validate as much as possible before processing anything
    """
    _validate_dc_update_params(
        name,
        resource_group_name,
        auto_upload_logs,
        auto_upload_metrics,
    )
    """

    # get dc resource from Azure
    dc_resource = client.azure_resource_client.get_generic_azure_resource(
        subscription=client.subscription,
        resource_group_name=resource_group_name,
        resource_provider_namespace=RESOURCE_PROVIDER_NAMESPACE,
        resource_type=INSTANCE_TYPE_DATA_CONTROLLER,
        resource_name=name,
        api_version=API_VERSION,
    )

    is_dc_directly_connected = _is_dc_directly_connected(dc_resource)

    if auto_upload_logs is not None:
        if not is_dc_directly_connected:
            raise ValidationError(
                "Automatic upload of logs is only supported for data "
                "controllers in direct connectivity mode"
            )

        _update_auto_upload_logs(dc_resource, auto_upload_logs, client)

    if auto_upload_metrics is not None:
        if not is_dc_directly_connected:
            raise ValidationError(
                "Automatic upload of metrics is only supported for data "
                "controllers in direct connectivity mode"
            )

        _update_auto_upload_metrics(
            dc_resource, resource_group_name, auto_upload_metrics, client
        )

    # update dc Azure resource
    response = (
        client.azure_resource_client.create_or_update_generic_azure_resource(
            subscription=client.subscription,
            resource_group_name=resource_group_name,
            resource_provider_namespace=RESOURCE_PROVIDER_NAMESPACE,
            resource_type=INSTANCE_TYPE_DATA_CONTROLLER,
            resource_name=name,
            api_version=API_VERSION,
            parameters=dc_resource,
            wait_for_response=False,
        )
    )

    return response


def dc_upgrade(
    client,
    namespace=None,
    target=None,
    dry_run=None,
    use_k8s=None,
    resource_group=None,
    name=None,
    nowait=False,
):
    try:
        cvo = client.args_to_command_value_object(
            {
                "namespace": namespace,
                "target": target,
                "dry_run": dry_run,
                "no_wait": nowait,
                "name": name,
                "resource_group": resource_group,
            }
        )
        client.services.dc.upgrade(cvo)
    except Exception as e:
        raise CLIError(e)


def dc_list_upgrade(client, namespace, use_k8s=None):
    stdout = client.stdout
    try:
        cvo = client.args_to_command_value_object(
            {"namespace": namespace, "use_k8s": use_k8s}
        )
        current_version, versions = client.services.dc.list_upgrades(cvo)

        stdout(
            "Found {0} valid versions.  The current datacontroller version is "
            "{1}.".format(len(versions), current_version)
        )

        for version in versions:
            if version == current_version:
                stdout(
                    "{0} << current version".format(version),
                    color=Fore.LIGHTGREEN_EX,
                )
            else:
                stdout(version)
    except Exception as e:
        raise CLIError(e)


def dc_endpoint_list(client, namespace, endpoint_name=None, use_k8s=None):
    """
    Retrieves the endpoints of the cluster
    """
    try:
        cvo = client.args_to_command_value_object(
            {"namespace": namespace, "endpoint_name": endpoint_name}
        )
        return client.services.dc.list_endpoints(cvo)
    except Exception as e:
        raise CLIError(e)


def dc_status_show(
    client, name=None, resource_group=None, namespace=None, use_k8s=None
):
    """
    Return the status of the data controller custom resource.
    """

    try:
        cvo = client.args_to_command_value_object(
            {
                "name": name,
                "resource_group": resource_group,
                "namespace": namespace,
            }
        )
        state = client.services.dc.get_status(cvo)

        if use_k8s:
            client.stdout(state.lower().capitalize())
        else:
            return state
    except (ValueError, Exception) as e:
        raise CLIError(e)


def dc_config_show(client, namespace=None, use_k8s=None):
    """
    Return the config of the data controller custom resource.
    """
    try:
        cvo = client.args_to_command_value_object({"namespace": namespace})
        return client.services.dc.get_config(cvo)
    except Exception as e:
        raise CLIError(e)


def dc_delete(
    client,
    name,
    namespace=None,
    resource_group=None,
    force=None,
    yes=None,
    use_k8s=None,
    no_wait=False,
):
    """
    Deletes the data controller.
    """
    try:
        stdout = client.stdout

        if not yes:
            stdout("")
            stdout(
                "This operation will delete everything inside of data "
                "controller `{}` which includes the Kubernetes "
                "secrets and services, etc.".format(name)
            )
            stdout(
                "Data stored on persistent volumes will get deleted if the "
                "storage class reclaim policy is set to "
                "delete/recycle."
            )
            stdout("")

            yes = prompt_y_n(
                "Do you want to continue with deleting "
                "the data controller `{}`?".format(name)
            )

        if yes != "yes" and yes is not True:
            stdout("Data controller not deleted. Exiting...")
            return

        cvo = client.args_to_command_value_object(
            {
                "name": name,
                "resource_group": resource_group,
                "namespace": namespace,
                "force": force,
                "no_wait": no_wait,
            }
        )
        client.services.dc.delete(cvo)

        stdout("Data controller `{}` deleted successfully.".format(name))
    except NoTTYException:
        raise CLIError("Please specify `--yes` in non-interactive mode.")
    except Exception as e:
        raise CLIError(e)


def dc_config_list(client, config_profile=None):
    """
    Lists available configuration file choices.
    """
    try:
        return client.services.dc.list_configs(config_profile)
    except (ValueError, Exception) as e:
        raise CLIError(e)


def dc_config_init(client, path=None, source=None, force=None):
    """
    Initializes a cluster configuration file for the user.
    """
    try:
        stdout = client.stdout
        config_dir = client.services.dc.get_deployment_config_dir()
        config_files = client.services.dc.get_deployment_config_files()

        try:
            if not path:
                path = prompt_for_input(
                    "Custom Config Profile Path:", "custom", False, False
                )
        except NoTTYException:
            # If non-interactive, default to custom directory
            path = "custom"

        # Read the available configs by name
        config_map = DeploymentConfigUtil.get_config_map(config_dir)

        if source:
            if source not in config_map.keys():
                raise ValueError(
                    "Invalid config source, please consult [dc "
                    "config list] for available sources"
                )
        elif not source:
            choices = DeploymentConfigUtil.get_config_display_names(config_map)

            # Filter out test profiles
            filtered_choices = list(filter(lambda c: "test" not in c, choices))

            # Prompt the user for a choice between configs
            stdout("Please choose a config:")
            source = prompt_for_choice(filtered_choices, choices[8])

        if os.path.isfile(path):
            raise FileExistsError(
                "Please specify a directory path. Path is a file: {0}".format(
                    path
                )
            )

        result = DeploymentConfigUtil.save_config_profile(
            path, source, config_dir, config_files, config_map, force
        )

        client.stdout("Created configuration profile in {}".format(result))
    except NoTTYException:
        raise CLIError("Please specify path and source in non-interactive mode")
    except (ValueError, Exception) as e:
        raise CLIError(e)


def dc_config_add(client, config_file, json_values):
    """
    Add new key and value to the given config file
    """
    try:
        config_object = DeploymentConfigUtil.config_add(
            config_file, json_values
        )
        DeploymentConfigUtil.write_config_file(config_file, config_object)
    except Exception as e:
        raise CLIError(e)


def dc_config_replace(client, config_file, json_values):
    """
    Replace the value of a given key in the given config file
    """
    try:
        config_object = DeploymentConfigUtil.config_replace(
            config_file, json_values
        )
        DeploymentConfigUtil.write_config_file(config_file, config_object)
    except Exception as e:
        raise CLIError(e)


def dc_config_remove(client, config_file, json_path):
    """
    Remove a key from the given config file
    """
    try:
        config_object = DeploymentConfigUtil.config_remove(
            config_file, json_path
        )
        DeploymentConfigUtil.write_config_file(config_file, config_object)
    except Exception as e:
        raise CLIError(e)


def dc_config_patch(client, config_file, patch_file):
    """
    Patch a given file against the given config file
    """
    try:
        config_object = DeploymentConfigUtil.config_patch(
            config_file, patch_file
        )
        DeploymentConfigUtil.write_config_file(config_file, config_object)
    except Exception as e:
        raise CLIError(e)


def dc_debug_copy_logs(
    client,
    namespace,
    container=None,
    target_folder=None,
    pod=None,
    resource_kind=None,
    resource_name=None,
    timeout=0,
    skip_compress=False,
    exclude_dumps=False,
    exclude_system_logs=False,
    use_k8s=None,  # not used
):
    """
    Copy Logs commands - requires kube config
    """
    try:
        client.services.dc.copy_logs(
            namespace,
            target_folder=target_folder,
            pod=pod,
            container=container,
            resource_kind=resource_kind,
            resource_name=resource_name,
            timeout=timeout,
            skip_compress=skip_compress,
            exclude_dumps=exclude_dumps,
            exclude_system_logs=exclude_system_logs,
        )
    except Exception as e:
        raise CLIError(e)


def dc_debug_dump(
    client,
    namespace,
    container="controller",
    target_folder="./output/dump",
    use_k8s=None,  # not used
):
    """
    Trigger dump for given container and copy out the dump file to given
    output folder
    """
    try:
        client.services.dc.capture_debug_dump(
            namespace, container, target_folder
        )
    except (NotImplementedError, Exception) as e:
        raise CLIError(e)


def dc_export(client, export_type, path, namespace, force=None, use_k8s=None):
    """
    Export metrics, logs or usage to a file.
    """
    try:
        if export_type.lower() not in ExportType.list():
            raise ValueError(
                "{} is not a supported type. "
                "Please specify one of the following: {}".format(
                    export_type, ExportType.list()
                )
            )

        path = check_prompt_export_output_file(path, force)

        client.services.dc.export(namespace, export_type, path)
    except NoTTYException:
        raise CLIError("Please specify `--force` in non-interactive mode.")
    except Exception as e:
        raise CLIError(e)


def arc_resource_kind_list(client):
    """
    Returns the list of available arc resource kinds which can be created in
    the cluster.
    """
    try:
        crd_file_dict = client.services.dc.get_crd_file_dict()
        named_path_dict = crd_file_dict.copy()
        return list(named_path_dict.keys())
    except Exception as e:
        raise CLIError(e)


def arc_resource_kind_get(client, kind, dest="template"):
    """
    Returns a package of crd.json and spec-template.json based on the given
    kind.
    """
    try:
        if not os.path.isdir(dest):
            os.makedirs(dest, exist_ok=True)

        crd_file_dict = client.services.dc.get_crd_file_dict()
        spec_file_dict = client.services.dc.get_spec_file_dict()

        # Make the resource name case insensitive
        local_crd_file_dict = {k.lower(): v for k, v in crd_file_dict.items()}
        local_spec_file_dict = {k.lower(): v for k, v in spec_file_dict.items()}
        kind_lower_case = kind.lower()

        if (
            kind_lower_case not in local_crd_file_dict
            or kind_lower_case not in local_spec_file_dict
        ):
            raise ValueError(
                "Invalid input kind. Pleae check resource kind list."
            )

        # crd in .yaml format and spec in .json format
        crd_file_path = local_crd_file_dict[kind_lower_case]
        spec_file_path = local_spec_file_dict[kind_lower_case]

        # Create the control plane CRD for the input kind.
        with open(crd_file_path, "r") as stream:
            crd = yaml.safe_load(stream)
            crd_pretty = json.dumps(crd, indent=4)
            with open(os.path.join(dest, "crd.json"), "w") as output:
                output.write(crd_pretty)

        # Copy spec.json template to the new path
        shutil.copy(spec_file_path, os.path.join(dest, "spec.json"))

        client.stdout(
            "{0} template created in directory: {1}".format(kind, dest)
        )

    except (ValueError, Exception) as e:
        raise CLIError(e)


##############################
# Azure / indirect only
##############################


def dc_upload(client, path):
    """
    Upload data file exported from a data controller to Azure.
    """

    import uuid
    from datetime import datetime

    try:
        if not os.path.exists(path):
            raise FileNotFoundError(
                'Cannot find file: "{}". Please provide the correct file name '
                "and try again".format(path)
            )

        with open(path, encoding="utf-8") as input_file:
            data = json.load(input_file)
            data = Sanitizer.sanitize_object(data, EXPORT_SANITIZERS)

            validate(data, EXPORT_DATA_JSON_SCHEMA)
    except Exception as e:
        raise CLIError(e)

    # Check expected properties
    #
    for expected_key in EXPORT_FILE_DICT_KEY:
        if expected_key not in data:
            raise ValueError(
                '"{}" is not found in the input file "{}".'.format(
                    expected_key, path
                )
            )

    export_type = data["exportType"]

    if not ExportType.has_value(export_type):
        raise ValueError(
            '"{}" is not a supported type. Please check your input file '
            '"{}".'.format(export_type, path)
        )

    # Create/Update shadow resource for data controller
    #
    data_controller = data["dataController"]

    try:
        data_controller_azure = client.get_dc_azure_resource(data_controller)
    except Exception as e:
        raise CLIError(
            "Upload failed. Unable to read data controller resource from Azure"
        ) from e

    set_azure_upload_status(data_controller, data_controller_azure)
    client.create_dc_azure_resource(data_controller)

    # Delete shadow resources for resource instances deleted from the cluster
    # in k8s
    #
    deleted = dict()

    for instance in data["deletedInstances"]:
        instance_key = "{}/{}.{}".format(
            instance["kind"],
            instance["instanceName"],
            instance["instanceNamespace"],
        )

        if instance_key not in deleted.keys():
            try:
                client.delete_azure_resource(instance, data_controller)
                deleted[instance_key] = True
            except Exception as e:
                client.stdout(
                    'Failed to delete Azure resource for "{}" in "{}".'.format(
                        instance["instanceName"], instance["instanceNamespace"]
                    )
                )
                client.stderr(e)
                continue

    # Create/Update shadow resources for resource instances still active in
    # the cluster in k8s
    #
    for instance in data["instances"]:
        client.create_azure_resource(instance, data_controller)

    data_timestamp = datetime.strptime(
        data["dataTimestamp"], "%Y-%m-%dT%H:%M:%S.%fZ"
    )

    # Upload metrics, logs or usage
    #
    try:
        if export_type == ExportType.metrics.value:
            metrics_upload(data["data"])
        elif export_type == ExportType.logs.value:
            customer_id, shared_key = _get_log_workspace_credentials_from_env(
                client
            )
            client.stdout('Log Analytics workspace: "{}"'.format(customer_id))
            for file in data["data"]:
                with open(file, encoding="utf-8") as input_file:
                    data = json.load(input_file)
                logs_upload(data["data"], customer_id, shared_key)
        elif export_type == "usage":
            if data_controller:
                client.stdout("\n")
                client.stdout("Start uploading usage...")
                correlation_vector = str(uuid.uuid4())
                for usage in data["data"]:
                    client.upload_usages_dps(
                        data_controller,
                        usage,
                        data["dataTimestamp"],
                        correlation_vector,
                    )

                if (
                    LAST_USAGE_UPLOAD_FLAG in data
                    and data[LAST_USAGE_UPLOAD_FLAG]
                ):
                    # Delete DC shadow resource to close out billing
                    #
                    client.delete_azure_resource(
                        resource=data_controller,
                        data_controller=data_controller,
                    )

                client.stdout("Usage upload is done.")
            else:
                client.stdout(
                    "No usage has been reported. Please wait for 24 hours if you "
                    "just deployed the Azure Arc enabled data services."
                )
        else:
            raise ValueError(
                '"{}" is not a supported type. Please check your input file '
                '"{}".'.format(export_type, path)
            )
    except Exception as ex:
        update_azure_upload_status(
            client, data_controller, export_type, data_timestamp, ex
        )
        raise

    update_azure_upload_status(
        client, data_controller, export_type, data_timestamp, None
    )

    # Update watermark after upload succeed for all three types of data
    timestamp_from_status_file = get_export_timestamp_from_file(export_type)
    timestamp_from_export_file = data_timestamp

    if timestamp_from_status_file < timestamp_from_export_file:
        update_upload_status_file(
            export_type,
            data_timestamp=timestamp_from_export_file.isoformat(
                sep=" ", timespec="milliseconds"
            ),
        )


def _is_dc_directly_connected(dc):
    """
    Return True if dc is directly connected mode. False otherwise.
    (this is determined by checking at the extended_location, "ConnectionMode"
    property is ignored, this is the same logic performed in the RP)
    """

    if dc.extended_location is None:
        return False

    if dc.extended_location.type.lower() != "customlocation":
        return False

    return True


def _update_auto_upload_logs(dc, auto_upload_logs, client):

    """
    Update auto upload logs properties. This includes asking for the
    log analytics workspace id/key if needed.
    :param dc: The data controller. The updated properties are changed on this
               object.
    :param auto_upload_logs: "true"/"false" (string, not boolean) indicating
    whether or not to enable auto upload.
    """

    dc.properties["k8sRaw"]["spec"]["settings"]["azure"][
        "autoUploadLogs"
    ] = auto_upload_logs

    if auto_upload_logs == "false":
        dc.properties["logAnalyticsWorkspaceConfig"] = None
        return

    if (
        "logAnalyticsWorkspaceConfig" not in dc.properties
        or dc.properties["logAnalyticsWorkspaceConfig"] is None
    ):
        dc.properties["logAnalyticsWorkspaceConfig"] = dict()

    (
        workspace_id,
        workspace_shared_key,
    ) = _get_log_workspace_credentials_from_env(client)

    dc.properties["logAnalyticsWorkspaceConfig"]["workspaceId"] = workspace_id
    dc.properties["logAnalyticsWorkspaceConfig"][
        "primaryKey"
    ] = workspace_shared_key


def _update_auto_upload_metrics(
    dc, resource_group_name, auto_upload_metrics, client
):
    """
    Update auto upload metrics property. This includes creating the necessary
    role assignments if needed.
    :param dc: The data controller. The updated property is changed on this
               object.
    :param resource_group_name: The data controller's resource group name.
    :param auto_upload_metrics: "true"/"false" (string, not boolean) indicating
    whether or not to enable auto upload.
    """

    if auto_upload_metrics == "true":
        assign_metrics_role_if_missing(
            dc.extended_location.name,
            resource_group_name,
            client.azure_resource_client,
        )

    dc.properties["k8sRaw"]["spec"]["settings"]["azure"][
        "autoUploadMetrics"
    ] = auto_upload_metrics


def assign_metrics_role_if_missing(
    custom_location_id, resource_group_name, azure_resource_client
):
    """
    Assign metrics publisher role to the extension identity.
    :param custom_location_id: Assign the role to the bootstrapper extension
           on this custom location.
    :param resource_group_name: The resource group name.
    :param azure_resource_client: Azure resource client used to assign the role.
    """
    metrics_role_description = ROLE_DESCRIPTIONS[
        MONITORING_METRICS_PUBLISHER_ROLE_ID
    ]

    extension_identity_principal_id = (
        azure_resource_client.get_extension_identity(custom_location_id)
    )

    logger.debug(
        f"Bootstrapper extension identity (principal id): "
        f"'{extension_identity_principal_id}'"
    )

    if azure_resource_client.has_role_assignment(
        extension_identity_principal_id,
        resource_group_name,
        MONITORING_METRICS_PUBLISHER_ROLE_ID,
        metrics_role_description,
    ):
        logger.debug(
            "Bootstrapper extension identity already has metrics publisher role."
        )
    else:
        logger.debug(
            f"Assigning '{metrics_role_description}' role to bootstrapper "
            f"extension identity..."
        )

        azure_resource_client.create_role_assignment(
            extension_identity_principal_id,
            resource_group_name,
            MONITORING_METRICS_PUBLISHER_ROLE_ID,
            metrics_role_description,
        )
