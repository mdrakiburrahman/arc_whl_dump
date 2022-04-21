# ------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# ------------------------------------------------------------------------------

"""Command definitions for `data control`."""
import uuid

from azure.cli.core.azclierror import ValidationError
from azext_arcdata.dc.constants import LAST_USAGE_UPLOAD_FLAG
from azext_arcdata.arm_sdk.dc.export_util import (
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
    connectivity_mode,
    name,
    # location,
    resource_group,
    infrastructure=None,
    no_wait=False,
    path=None,
    profile_name=None,
    storage_class=None,
    # -- direct --
    auto_upload_logs=None,
    auto_upload_metrics=None,
    custom_location=None,
    cluster_name=None,
    # -- indirect --
    annotations=None,
    namespace=None,
    labels=None,
    location=None,
    logs_ui_private_key_file=None,
    logs_ui_public_key_file=None,
    metrics_ui_private_key_file=None,
    metrics_ui_public_key_file=None,
    service_annotations=None,
    service_labels=None,
    storage_annotations=None,
    storage_labels=None,
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
                "connectivity_mode": connectivity_mode,
                "name": name,
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
                "cluster_name": cluster_name,
                "namespace": namespace,
                "no_wait": no_wait,
            }
        )

        dc = client.services.dc.create(cvo)
        if no_wait:
            stdout(
                f"The data controller '{name}' is being created in the "
                f"background, to check status run:\n\naz arcdata dc status "
                f"show -n {name} -g {resource_group} --query properties."
                f"k8SRaw.status"
            )
        return dc
    except (NoTTYException, ValueError, Exception) as e:
        raise CLIError(e)


def dc_update(
    client,
    name=None,
    resource_group_name=None,
    auto_upload_logs=None,
    auto_upload_metrics=None,
    # k8s only
    use_k8s=None,
    namespace=None,
    desired_version=None,
    maintenance_start=None,
    maintenance_duration=None,
    maintenance_recurrence=None,
    maintenance_time_zone=None,
    maintenance_enabled=None,
):
    """
    Update data controller properties.
    """
    cvo = client.args_to_command_value_object()
    return client.services.dc.update(cvo)


def dc_upgrade(
    client,
    namespace=None,
    desired_version=None,
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
                "target": desired_version,
                "dry_run": dry_run,
                "no_wait": nowait,
                "name": name,
                "resource_group": resource_group,
            }
        )
        client.services.dc.upgrade(cvo)
    except Exception as e:
        raise CLIError(e)


def mw_update(
    client,
    namespace=None,
    desired_version=None,
    use_k8s=None,
    maintenance_start=None,
    maintenance_duration=None,
    maintenance_recurrence=None,
    maintenance_time_zone=None,
):
    """
    Pass-through maintenance window update command
    """
    try:
        cvo = client.args_to_command_value_object()
        client.services.dc.update_maintenance_window(cvo)
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
