# ------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# ------------------------------------------------------------------------------

"""Command definitions for `data control`."""

from azext_arcdata.dc.exceptions import ArcError
from azext_arcdata.dc.constants import (
    CONFIG_DIR,
    HELP_DIR,
    CONTROL_CONFIG_FILENAME,
    CONFIG_FILES,
    DATA_CONTROLLER_CRD,
    INFRASTRUCTURE_AUTO,
    INFRASTRUCTURE_CR_ALLOWED_VALUES,
    LAST_BILLING_USAGE_FILE,
    LAST_USAGE_UPLOAD_FLAG,
    POSTGRES_CRD,
    SQLMI_CRD,
    SQLMI_RESTORE_TASK_CRD,
    EXPORT_TASK_CRD,
    DAG_CRD,
    DIRECT,
    EXPORT_TASK_RESOURCE_KIND_PLURAL,
    EXPORT_TASK_CRD_VERSION,
    TASK_API_GROUP,
    MAX_POLLING_ATTEMPTS,
    MONITOR_CRD,
    EXPORT_COMPLETED_STATE,
    CRD_FILE_DICT,
    SPEC_FILE_DICT,
)
from azext_arcdata.dc.azure import constants as azure_constants
from azext_arcdata.dc.export_util import (
    add_last_upload_flag,
    ExportType,
    logs_upload,
    metrics_upload,
    _get_log_workspace_credentials_from_env,
    EXPORT_DATA_JSON_SCHEMA,
    EXPORT_FILE_DICT_KEY,
    EXPORT_SANITIZERS,
    get_export_timestamp_from_file,
    get_export_timestamp,
    set_azure_upload_status,
    update_azure_upload_status,
    update_upload_status_file,
    generate_export_file_name,
)
from azext_arcdata.dc.common_util import (
    validate_infrastructure_value,
    get_kubernetes_infra,
    validate_dc_create_params,
    write_file,
    write_output_file,
)
from azext_arcdata.core.kubernetes import create_namespace_with_retry
from azext_arcdata.core.serialization import Sanitizer
from azext_arcdata.kubernetes_sdk.client import K8sApiException, KubernetesError
from azext_arcdata.kubernetes_sdk.models.data_controller_custom_resource import (
    DataControllerCustomResource,
)
from azext_arcdata.kubernetes_sdk.models.custom_resource_definition import (
    CustomResourceDefinition,
)
from azext_arcdata.kubernetes_sdk.models.custom_resource import CustomResource
from azext_arcdata.kubernetes_sdk.models.export_task_custom_resource import (
    ExportTaskCustomResource,
)
import azext_arcdata.core.kubernetes as kubernetes_util
from azext_arcdata.core.constants import (
    ARC_GROUP,
    DATA_CONTROLLER_CRD_VERSION,
    ARC_NAMESPACE_LABEL,
    DATA_CONTROLLER_PLURAL,
    USE_K8S_EXCEPTION_TEXT,
)
from azext_arcdata.core.prompt import (
    prompt_for_input,
    prompt_for_choice,
    prompt_assert,
    prompt_y_n,
)
from azext_arcdata.core.util import (
    DeploymentConfigUtil,
    time_ns,
    check_and_set_kubectl_context,
    retry,
    read_config,
    check_missing,
    control_config_check,
    parse_labels,
    is_windows,
)
from azext_arcdata.core.debug import (
    copy_debug_logs,
    take_dump,
)

from humanfriendly.terminal.spinners import AutomaticSpinner
from jsonschema import validate
from knack.prompting import NoTTYException
from knack.log import get_logger
from knack.cli import CLIError
from urllib3.exceptions import NewConnectionError, MaxRetryError

import json
import os
import yaml
import time
import shutil

logger = get_logger(__name__)

CONNECTION_RETRY_ATTEMPTS = 12
RETRY_INTERVAL = 5


def dc_create(
    client,
    namespace,
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
    use_k8s=None,
):
    """
    If an argument is not provided, the user will be prompted for the needed
    values NoTTY Scenario: provide a config_profile, profile_name
    """
    try:
        stdout = client.stdout

        if connectivity_mode.lower() != DIRECT and not use_k8s:
            raise ValueError(
                "For indirect connectivity mode, please include "
                "the [--use-k8s] argument."
            )

        subscription = client.subscription or prompt_assert("Subscription: ")
        stdout("\nUsing subscription '{}'.".format(subscription))

        # -- Check Kubectl Context --
        check_and_set_kubectl_context()
        namespace = namespace or client.namespace

        # Validate params
        validate_dc_create_params(
            name,
            namespace,
            subscription,
            location,
            resource_group,
            connectivity_mode,
            infrastructure,
            profile_name,
            path,
        )

        # For direct connectivity mode disable dc creation
        if connectivity_mode.lower() == DIRECT:
            raise ArcError(
                "Only indirect connectivity mode is allowed. "
                "Please use the Azure Portal to deploy Arc data controller in "
                "direct connectivity mode."
            )

        # Get infrastructure if needed.
        if infrastructure == INFRASTRUCTURE_AUTO:
            infrastructure = _detect_or_prompt_infrastructure(client)

        #  -- User entered an existing configuration type
        if profile_name:
            path = os.path.join(CONFIG_DIR, profile_name)
            if not os.path.isdir(path):
                raise ValueError(
                    "Profile name {0} does not exist.".format(
                        os.path.basename(profile_name)
                    )
                )

        if labels:
            try:
                stdout("labels set {}", labels)
                parse_labels(labels)
            except ValueError as e:
                raise CLIError("Labels invalid: {}", e)

        if annotations:
            try:
                stdout("annotations set {}", annotations)
                parse_labels(annotations)
            except ValueError as e:
                raise CLIError("Annotations invalid: {}", e)

        if service_labels:
            try:
                parse_labels(service_labels)
            except ValueError as e:
                raise CLIError("Service labels invalid: {}", e)

        if service_annotations:
            try:
                parse_labels(service_annotations)
            except ValueError as e:
                raise CLIError("Service annotations invalid: {}", e)

        if storage_labels:
            try:
                parse_labels(storage_labels)
            except ValueError as e:
                raise CLIError("Storage labels invalid: {}", e)

        if storage_annotations:
            try:
                parse_labels(storage_annotations)
            except ValueError as e:
                raise CLIError("Storage annotations invalid: {}", e)

        # -- Configuration Directory --
        if not path:
            profiles = DeploymentConfigUtil.get_config_map(CONFIG_DIR)

            # Prompt the user for a choice between configs
            stdout("Please choose a deployment configuration: ")
            stdout(
                "To see more info please exit create and use command "
                "[arcdata dc config list -c <config_profile>]"
            )
            choices = DeploymentConfigUtil.get_config_display_names(profiles)
            # Filter out test profiles
            filtered_choices = list(filter(lambda c: "test" not in c, choices))
            result = prompt_for_choice(filtered_choices, choices[8])

            path = os.path.join(CONFIG_DIR, profiles[result.lower()])

        # -- Required Environment Variables --
        """
        if sys.stdin.isatty():
            read_environment_variables(ARC_NAME, True)
        else:
            check_environment_variables(ARC_NAME)
        """

        # -- Read json into python dictionary --
        config_object = read_config(path, CONTROL_CONFIG_FILENAME)

        # If no infrastructure parameter was provided, try to get it from the file
        if infrastructure is None:
            infrastructure = _get_infrastructure_from_file_or_auto(
                client, config_object
            )

        dc_cr = CustomResource.decode(
            DataControllerCustomResource, config_object
        )
        args = locals()
        dc_cr.apply_args(**args)

        dc_encoding = dc_cr.encode()
        # -- Get help documentation for missing values --
        help_object = read_config(HELP_DIR, CONTROL_CONFIG_FILENAME)
        # -- Check for missing values in the config object --
        check_missing(
            stdout, False, dc_encoding, help_object, CONTROL_CONFIG_FILENAME
        )
        # -- Check if dc config is valid
        # control_config_check(stdout, dc_encoding)
        control_config_check(dc_encoding)

        # Rehydrate from config object which might have been updated from
        # prompts by check_missing
        dc_cr = CustomResource.decode(DataControllerCustomResource, dc_encoding)

        annotations = {
            "openshift.io/sa.scc.supplemental-groups": "1000700001/10000",
            "openshift.io/sa.scc.uid-range": "1000700001/10000"
        }

        # prepare the namespace
        create_namespace_with_retry(
            dc_cr.metadata.namespace, ARC_NAMESPACE_LABEL, annotations
        )

        crd_files = [
            POSTGRES_CRD,
            SQLMI_CRD,
            SQLMI_RESTORE_TASK_CRD,
            EXPORT_TASK_CRD,
            DAG_CRD,
            MONITOR_CRD,
            DATA_CONTROLLER_CRD,
        ]

        # Create the control plane CRD if it doesn't already exist
        for crd_file in crd_files:
            with open(crd_file, "r") as stream:
                temp = yaml.safe_load(stream)
                crd = CustomResourceDefinition(temp)
                retry(
                    lambda: client.apis.kubernetes.create_or_replace_custom_resource_definition(
                        crd
                    ),
                    retry_count=CONNECTION_RETRY_ATTEMPTS,
                    retry_delay=RETRY_INTERVAL,
                    retry_method="create custom resource definition",
                    retry_on_exceptions=(
                        NewConnectionError,
                        MaxRetryError,
                        K8sApiException,
                    ),
                )

        # Create cluster role for metricsdc
        client.create_cluster_role_for_monitoring(dc_cr, namespace)

        # Create cluster role for data controller
        client.create_cluster_role_for_data_controller(namespace)

        # -- attempt to create cluster --
        stdout("")
        stdout("Deploying data controller")
        stdout("")
        stdout(
            "NOTE: Data controller creation can take a significant amount of "
            "time depending on"
        )
        stdout(
            "configuration, network speed, and the number of nodes in the "
            "cluster."
        )
        stdout("")

        response, deployed_cr = client.dc_create(crd, dc_cr)

        while not kubernetes_util.is_instance_ready(deployed_cr):
            time.sleep(5)
            logger.info("Data controller service is not ready yet.")

            response = retry(
                lambda: client.apis.kubernetes.get_namespaced_custom_object(
                    dc_cr.metadata.name,
                    dc_cr.metadata.namespace,
                    group=ARC_GROUP,
                    version=DATA_CONTROLLER_CRD_VERSION,
                    plural=DATA_CONTROLLER_PLURAL,
                ),
                retry_count=CONNECTION_RETRY_ATTEMPTS,
                retry_delay=RETRY_INTERVAL,
                retry_method="get namespaced custom object",
                retry_on_exceptions=(
                    NewConnectionError,
                    MaxRetryError,
                    KubernetesError,
                ),
            )

            deployed_cr = CustomResource.decode(
                DataControllerCustomResource, response
            )
        stdout("Data controller successfully deployed.")
    except NoTTYException:
        raise CLIError(
            "Please specify --profile-name or --path in non-interactive mode."
        )
    except (ValueError, ArcError, Exception) as e:
        raise CLIError(e)


def dc_endpoint_list(client, namespace, endpoint_name=None, use_k8s=None):
    """
    Retrieves the endpoints of the cluster
    """
    try:
        if not use_k8s:
            raise ValueError(USE_K8S_EXCEPTION_TEXT)

        return client.monitor_endpoint_list(namespace, endpoint_name)
    except Exception as e:
        raise CLIError(e)


def dc_status_show(client, namespace=None, use_k8s=None):
    """
    Return the status of the data controller custom resource.
    """
    try:
        if not use_k8s:
            raise ValueError(USE_K8S_EXCEPTION_TEXT)

        # -- Check Kubectl Context --
        check_and_set_kubectl_context()
        namespace = namespace or client.namespace

        response = client.apis.kubernetes.list_namespaced_custom_object(
            namespace,
            group=ARC_GROUP,
            version=DATA_CONTROLLER_CRD_VERSION,
            plural=DATA_CONTROLLER_PLURAL,
        )

        dcs = response.get("items")

        if not dcs:
            client.stdout(
                "No data controller exists in Kubernetes namespace `{}`.".format(
                    namespace
                )
            )
        else:
            cr = CustomResource.decode(DataControllerCustomResource, dcs[0])

            state = cr.status.state
            if state:
                client.stdout(state.lower().capitalize())
            else:
                client.stderr(
                    "Status unavailable for data controller `{0}` in Kubernetes namespace "
                    "`{1}`.".format(cr.metadata.name, namespace)
                )

    except Exception as e:
        raise CLIError(e)


def dc_config_show(client, namespace=None, use_k8s=None):
    """
    Return the config of the data controller custom resource.
    """
    try:
        if not use_k8s:
            raise ValueError(USE_K8S_EXCEPTION_TEXT)

        # -- Check Kubectl Context --
        check_and_set_kubectl_context()
        namespace = namespace or client.namespace

        response = client.apis.kubernetes.list_namespaced_custom_object(
            namespace,
            group=ARC_GROUP,
            version=DATA_CONTROLLER_CRD_VERSION,
            plural=DATA_CONTROLLER_PLURAL,
        )

        dcs = response.get("items")

        if not dcs:
            client.stdout(
                "No data controller exists in Kubernetes namespace `{}`.".format(
                    namespace
                )
            )
        else:
            return dcs[0]

    except Exception as e:
        raise CLIError(e)


def dc_delete(client, name, namespace, force=None, yes=None):
    """
    Deletes the data controller - requires kube config and env var
    """
    try:
        stdout = client.stdout
        namespace = namespace or client.namespace

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
            msg = "Data controller not deleted. Exiting..."
            return msg

        # -- Check Kubectl Context --
        check_and_set_kubectl_context()

        # -- Check existence of data controller --
        if not client.apis.kubernetes.namespaced_custom_object_exists(
            name,
            namespace,
            group=ARC_GROUP,
            version=DATA_CONTROLLER_CRD_VERSION,
            plural=DATA_CONTROLLER_PLURAL,
        ):
            raise CLIError(
                "Data controller `{}` does not exist in Kubernetes namespace `{}`.".format(
                    name, namespace
                )
            )

        # -- Check that connectivity mode is indirect --
        connection_mode = client.get_data_controller(namespace).get(
            "connectionMode"
        )

        if connection_mode == DIRECT:
            raise ArcError(
                "Performing this action from az using the --use-k8s parameter is only allowed using "
                "indirect mode. Please use the Azure Portal to perform this "
                "action in direct connectivity mode."
            )

        # -- Calculate usage at time of deletion --
        client.calculate_usage(namespace=namespace, exclude_curr_period=False)

        # -- Check existence of data services --
        crd_files = [POSTGRES_CRD, SQLMI_CRD]

        for crd_file in crd_files:
            # Create the control plane CRD if it doesn't already exist
            with open(crd_file, "r") as stream:
                temp = yaml.safe_load(stream)
                crd = CustomResourceDefinition(temp)
                cr_list = client.apis.kubernetes.list_namespaced_custom_object(
                    namespace, crd=crd
                )
                if cr_list["items"]:
                    if not force:
                        raise ArcError(
                            "Instances of `{}` are deployed. Cannot delete "
                            "data controller `{}`. Please delete these "
                            "instances before deleting the data controller or "
                            "use --force.".format(crd.kind, name)
                        )
                    else:
                        stdout("Deleting instances of `{}`.".format(crd.kind))
                        for item in cr_list["items"]:
                            cr_name = item["metadata"]["name"]
                            client.apis.kubernetes.delete_namespaced_custom_object(
                                name=cr_name, namespace=namespace, crd=crd
                            )
                            stdout("`{}` deleted.".format(cr_name))

        stdout("Exporting the remaining resource usage information...")

        usage_file_name = LAST_BILLING_USAGE_FILE.format(name)
        # TODO: dc_export(client, "usage", usage_file_name, namespace, force=True)

        usage_file_created = os.path.exists(usage_file_name)

        if usage_file_created:
            add_last_upload_flag(usage_file_name)
            stdout(
                "Please run 'az arcdata arc dc upload -p {}' to complete the "
                "deletion of data controller {}.".format(usage_file_name, name)
            )

        stdout("Deleting data controller `{}`.".format(name))

        # -- attempt to delete cluster --
        client.dc_delete(namespace, name)

        # Delete the monitor and control plane CRD
        crd_files = [MONITOR_CRD, DATA_CONTROLLER_CRD]

        for crd_file in crd_files:
            with open(crd_file, "r") as stream:
                temp = yaml.safe_load(stream)
                crd = CustomResourceDefinition(temp)
                client.apis.kubernetes.delete_custom_resource_definition(crd)

        stdout("Data controller `{}` deleted successfully.".format(name))

    except NoTTYException:
        raise CLIError("Please specify `--yes` in non-interactive mode.")
    except ArcError as e:
        raise CLIError(e)
    except KubernetesError as e:
        raise CLIError(e)
    except K8sApiException as e:
        raise CLIError(e)
    except Exception as e:
        raise CLIError(e)


def dc_config_list(client, config_profile=None):
    """
    Lists available configuration file choices.
    """
    try:
        configs = DeploymentConfigUtil.config_list(CONFIG_DIR, config_profile)

        # Filter out test profiles
        filtered_configs = list(filter(lambda c: "test" not in c, configs))

        return filtered_configs

    except ValueError as e:
        raise CLIError(e)
    except Exception as e:
        raise CLIError(e)


def dc_config_init(client, path=None, source=None, force=None):
    """
    Initializes a cluster configuration file for the user.
    """
    try:
        try:
            if not path:
                path = prompt_for_input(
                    "Custom Config Profile Path:", "custom", False, False
                )
        except NoTTYException:
            # If non-interactive, default to custom directory
            path = "custom"

        stdout = client.stdout

        # Read the available configs by name
        config_map = DeploymentConfigUtil.get_config_map(CONFIG_DIR)

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
            path, source, CONFIG_DIR, CONFIG_FILES, config_map, force
        )

        client.stdout("Created configuration profile in {}".format(result))

    except ValueError as e:
        raise CLIError(e)
    except NoTTYException:
        raise CLIError("Please specify path and source in non-interactive mode")
    except Exception as e:
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
    use_k8s=None,
):
    """
    Copy Logs commands - requires kube config
    """
    try:
        if not use_k8s:
            raise ValueError(USE_K8S_EXCEPTION_TEXT)

        # -- Check Kubectl Context --
        check_and_set_kubectl_context()
        namespace = namespace or client.namespace

        copy_debug_logs(
            namespace,
            target_folder,
            pod,
            container,
            resource_kind,
            resource_name,
            timeout,
            skip_compress,
            exclude_dumps,
            exclude_system_logs,
        )

    except (ArcError, NotImplementedError, Exception) as e:
        raise CLIError(e)


def dc_debug_dump(
    client,
    namespace,
    container="controller",
    target_folder="./output/dump",
    use_k8s=None,
):
    """
    Trigger dump for given container and copy out the dump file to given
    output folder
    """
    try:
        # The following error is misleading. All the framework, functions,
        # etc. to perform dump are in place and were working at the time I
        # wrote this comment--except they are not adjusted to the new non-root
        # world, where CAP_SYS_PTRACE needs to be enabled in order to get a
        # core dump. So the shell script that gets called in the controller
        # pod does nothing useful.
        #
        # Therefore, disabling the dump call until we can figure out
        # how we want to handle this. -safeitle, 07/21/2021
        #
        raise NotImplementedError(
            "'az arcdata dc debug dump' currently not "
            "implemented in this release. "
        )

        if not use_k8s:
            raise ValueError(USE_K8S_EXCEPTION_TEXT)
        # -- Check Kubectl Context --
        check_and_set_kubectl_context()
        namespace = namespace or client.namespace

        take_dump(namespace, container, target_folder)
    except (ArcError, NotImplementedError, Exception) as e:
        raise CLIError(e)


def dc_export(client, export_type, path, namespace, force=None, use_k8s=None):
    """
    Export metrics, logs or usage to a file.
    """
    from datetime import datetime, timedelta

    stdout = client.stdout
    cluster_name = namespace or client.namespace

    info_msg = (
        'This option exports {} of all instances in "{}" to the file: "{}".'
    )

    # -- Check Kubectl Context --
    check_and_set_kubectl_context()

    try:

        if not use_k8s:
            raise ValueError(USE_K8S_EXCEPTION_TEXT)

        if export_type.lower() not in ExportType.list():
            raise ValueError(
                "{} is not a supported type. "
                "Please specify one of the following: {}".format(
                    export_type, ExportType.list()
                )
            )

        path = _check_prompt_export_output_file(path, force)
        data_controller = client.get_data_controller(cluster_name)

        content = {
            "exportType": export_type,
            "dataController": data_controller,
            "dataTimestamp": datetime.now().isoformat(
                sep=" ", timespec="milliseconds"
            ),
            "instances": [],
            "data": [],
        }

        if (
            data_controller["connectionMode"].lower()
            == azure_constants.DIRECT_CONNECTIVITY_MODE
        ):
            raise ValueError(
                "Export is not supported for direct connectivity mode."
            )

        # Create export custom resource
        # Get startTime and endTime of export
        end_time = datetime.utcnow()
        start_time = get_export_timestamp(export_type)
        export_cr_name = "export-{}-{}".format(
            export_type,
            end_time.strftime("%Y-%m-%d-%H-%M-%S")
            + "-"
            + str(time_ns() // 1000000),
        )

        with open(EXPORT_TASK_CRD, "r") as stream:
            temp = yaml.safe_load(stream)
            crd = CustomResourceDefinition(temp)

            spec_object = {
                "apiVersion": crd.group + "/" + crd.stored_version,
                "kind": crd.kind,
                "metadata": {
                    "name": export_cr_name,
                    # "namespace": client.profile.active_context.namespace,
                    "namespace": cluster_name,
                },
                "spec": {
                    "exportType": export_type,
                    "startTime": start_time,
                    "endTime": end_time,
                },
            }

            cr = CustomResource.decode(ExportTaskCustomResource, spec_object)
            cr.validate(client.apis.kubernetes)

            response = retry(
                lambda: client.apis.kubernetes.create_namespaced_custom_object_with_body(
                    spec_object, cr=cr, plural=crd.plural, ignore_conflict=True
                ),
                retry_count=CONNECTION_RETRY_ATTEMPTS,
                retry_delay=RETRY_INTERVAL,
                retry_method="create namespaced custom object",
                retry_on_exceptions=(
                    NewConnectionError,
                    MaxRetryError,
                    KubernetesError,
                ),
            )

            if response:
                client.stdout(
                    "Export custom resource: {} is created.".format(
                        export_cr_name
                    )
                )
            else:
                raise CLIError(
                    "Failed to create export custom resource: {}".format(
                        export_cr_name
                    )
                )

            index_file_path = _get_export_task_file_path(
                client, export_cr_name, namespace
            )

            if (
                index_file_path == "No data are exported"
                or index_file_path is None
            ):
                raise CLIError("No data are exported.")

            controller_endpoint = client.apis.controller.get_endpoint(namespace)

            # Get download path
            index_file = retry(
                client.apis.controller.get_export_file_path,
                index_file_path,
                controller_endpoint,
                retry_count=CONNECTION_RETRY_ATTEMPTS,
                retry_delay=RETRY_INTERVAL,
                retry_method="download index file",
                retry_on_exceptions=(NewConnectionError, MaxRetryError),
            )

            index_file_json = index_file

            data_controller["publicKey"] = index_file_json[
                "publicSigningCertificate"
            ]
            content["dataTimestamp"] = index_file_json["endTime"]

            instances = client.list_all_custom_resource_instances(cluster_name)
            content["instances"] = instances

            active_instances = dict.fromkeys(
                map(
                    lambda x: "{}/{}.{}".format(
                        x["kind"], x["instanceName"], x["instanceNamespace"]
                    ),
                    instances,
                )
            )

            deleted_instances = index_file_json["customResourceDeletionList"]

            # Ignored instances which were deleted but subsequently recreated,
            # as their will be updated
            content["deletedInstances"] = list(
                filter(
                    lambda x: "{}/{}.{}".format(
                        x["kind"], x["instanceName"], x["instanceNamespace"]
                    )
                    not in active_instances.keys(),
                    deleted_instances,
                )
            )

            stdout(info_msg.format(export_type, cluster_name, path))

            if (
                export_type.lower() == ExportType.metrics.value
                or export_type.lower() == ExportType.usage.value
            ):
                file = retry(
                    client.apis.controller.get_export_file_path,
                    index_file_json["dataFilePathList"][0],
                    controller_endpoint,
                    retry_count=CONNECTION_RETRY_ATTEMPTS,
                    retry_delay=RETRY_INTERVAL,
                    retry_method="download data file",
                    retry_on_exceptions=(NewConnectionError, MaxRetryError),
                )

                if file:
                    content["data"] = file
                    write_output_file(path, content)
                    stdout("{0} are exported to {1}".format(export_type, path))
                else:
                    allowNodeMetricsCollection = content["dataController"][
                        "k8sRaw"
                    ]["spec"]["security"]["allowNodeMetricsCollection"]
                    allowPodMetricsCollection = content["dataController"][
                        "k8sRaw"
                    ]["spec"]["security"]["allowPodMetricsCollection"]
                    if (
                        not allowNodeMetricsCollection
                        or not allowPodMetricsCollection
                    ):
                        stdout(
                            "There are no metrics available for export. "
                            "Please follow the documentation to ensure that "
                            "allowNodeMetricsCollection and/or "
                            "allowPodMetricsCollection are set to true to "
                            "collect metrics and then export them."
                        )
                    else:
                        stdout(
                            "Failed to get metrics. "
                            "Please ensure you connect to the correct cluster "
                            "and the instances have metrics."
                        )
            elif export_type.lower() == ExportType.logs.value:
                file_index = 0
                data_files = []
                for data_file_path in index_file_json["dataFilePathList"]:
                    file = retry(
                        client.apis.controller.get_export_file_path,
                        data_file_path,
                        controller_endpoint,
                        retry_count=CONNECTION_RETRY_ATTEMPTS,
                        retry_delay=RETRY_INTERVAL,
                        retry_method="download data file",
                        retry_on_exceptions=(NewConnectionError, MaxRetryError),
                    )

                    if file:
                        data = file
                        file_path = generate_export_file_name(path, file_index)
                        write_file(
                            file_path,
                            data,
                            export_type,
                            index_file_json["endTime"],
                        )
                        file_index += 1
                        data_files.append(file_path)

                if len(data_files) > 0:
                    content["data"] = data_files
                    write_output_file(path, content)
                    stdout("{0} are exported to {1}".format(export_type, path))
                else:
                    stdout("No log is exported.")

    except NoTTYException:
        raise CLIError("Please specify `--force` in non-interactive mode.")
    except Exception as e:
        raise CLIError(e)


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


def arc_resource_kind_list(client):
    """
    Returns the list of available arc resource kinds which can be created in
    the cluster.
    """
    try:
        namd_path_dict = CRD_FILE_DICT.copy();
        return list(namd_path_dict.keys())
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

        # Make the resource name case insensitive
        local_crd_file_dict = {k.lower() : v for k,v in CRD_FILE_DICT.items()}
        local_spec_file_dict = {k.lower() : v for k,v in SPEC_FILE_DICT.items()}
        kind_lower_case = kind.lower()

        if kind_lower_case not in local_crd_file_dict or kind_lower_case not in local_spec_file_dict:
            raise ValueError("Invalid input kind. Pleae check resource kind list.")

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

    except Exception as e:
        raise CLIError(e)


def _check_prompt_export_output_file(file_path, force):
    """
    Checks if export output file exists, and prompt if necessary.
    """
    # Check if file exists
    export_file_exists = True
    overwritten = False

    while export_file_exists and not overwritten:
        export_file_exists = os.path.exists(file_path)
        if not force and export_file_exists:
            try:
                yes = prompt_y_n(
                    "{} exists already, do you want to overwrite it?".format(
                        file_path
                    )
                )
            except NoTTYException as e:
                raise NoTTYException(
                    "{} Please make sure the file does not exist in a"
                    " non-interactive environment".format(e)
                )

            overwritten = True if yes else False

            if overwritten:
                os.remove(file_path)
            else:
                file_path = prompt_for_input(
                    "Please provide a file name with the path: "
                )
                export_file_exists = True
                overwritten = False

        elif force:
            overwritten = True
            if export_file_exists:
                os.remove(file_path)

    return file_path


def _get_export_task_file_path(client, name, namespace):
    import time

    retry_count = 0

    while retry_count < MAX_POLLING_ATTEMPTS:
        export_task = retry(
            lambda: client.apis.kubernetes.get_namespaced_custom_object(
                name=name,
                namespace=namespace,
                group=TASK_API_GROUP,
                version=EXPORT_TASK_CRD_VERSION,
                plural=EXPORT_TASK_RESOURCE_KIND_PLURAL,
            ),
            retry_count=CONNECTION_RETRY_ATTEMPTS,
            retry_delay=RETRY_INTERVAL,
            retry_method="get namespaced custom object",
            retry_on_exceptions=(NewConnectionError, MaxRetryError),
        )

        state = export_task.get("status", {}).get("state")
        if state is None:
            retry_count += 1
            time.sleep(20)
        else:
            client.stdout(
                "Export custom resource: {0} state is {1}".format(name, state)
            )
            if state == EXPORT_COMPLETED_STATE:
                logger.debug(export_task)
                return export_task.get("status", {}).get("path")
            else:
                time.sleep(20)

    raise CLIError("Export custom resource:{0} is not ready.".format(name))


def _detect_or_prompt_infrastructure(client):
    """
    Try to detect the infrastructure from the node's spec.provider_id. If not possible prompt for it / fail (based on TTY).
    """

    logger.debug("Trying to detect infrastructure.")

    try:
        infrastructure = get_kubernetes_infra(client)
        return infrastructure
    except ArcError as e:
        try:
            logger.info(
                "Unable to detect infrastructure: %s. Will try to prompt for it.",
                e,
            )
            client.stdout(
                "Please select the infrastructure for the data controller:"
            )
            infrastructure = prompt_for_choice(INFRASTRUCTURE_CR_ALLOWED_VALUES)
            return infrastructure
        except NoTTYException:
            raise CLIError(
                "Unable to determine the infrastructure for the data controller. Please provide an '--infrastructure' value other than 'auto'."
            ) from e


def _get_infrastructure_from_file(config_object):
    """
    Get infrastructure from the confg file. If no "spec.infrastructure" was provided, return None. Otherwise validate it and raise an error if not valid.
    """

    logger.debug("Looking for infrastructure in control.json")

    try:
        infra = config_object["spec"]["infrastructure"]
        logger.debug("Found infrastructure in control.json: %s", infra)
        validate_infrastructure_value(infra)
        return infra
    except KeyError:
        return None


def _get_infrastructure_from_file_or_auto(client, config_object):
    """
    Get and validate infrastructure form config_object. If missing, detect or prompt for it.
    """

    # try to get infrastructure from file
    infrastructure = _get_infrastructure_from_file(config_object)

    # detect or prompt for it
    if infrastructure is None:
        infrastructure = _detect_or_prompt_infrastructure(client)

    return infrastructure