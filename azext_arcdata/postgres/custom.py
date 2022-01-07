# ------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# -----------------------------------------------------------------------------

from knack.cli import CLIError
from azext_arcdata.core.util import (
    FileUtil,
    is_windows,
    retry,
    check_and_set_kubectl_context,
    get_config_from_template,
)
from azext_arcdata.kubernetes_sdk.client import (
    KubernetesClient,
    KubernetesError,
    K8sApiException,
    http_status_codes,
)
from azext_arcdata.kubernetes_sdk.models.data_controller_custom_resource import (
    DataControllerCustomResource,
)
from azext_arcdata.kubernetes_sdk.models.custom_resource_definition import (
    CustomResourceDefinition,
)
from azext_arcdata.kubernetes_sdk.models.custom_resource import CustomResource
from azext_arcdata.core.constants import (
    AZDATA_PASSWORD,
    MGMT_PROXY,
    ARC_GROUP,
    DATA_CONTROLLER_CRD_VERSION,
    DATA_CONTROLLER_PLURAL,
    USE_K8S_EXCEPTION_TEXT,
)
from azext_arcdata.core.prompt import prompt, prompt_pass, prompt_y_n
from azext_arcdata.postgres.constants import (
    RESOURCE_KIND,
    COMMAND_UNIMPLEMENTED,
    API_GROUP,
    DEFAULT_ENGINE_VERSION,
)
from azext_arcdata.postgres.util import is_valid_connectivity_mode
from .models.postgres_cr_model import (
    PostgresqlCustomResource,
)
from azext_arcdata.core.util import DeploymentConfigUtil
from collections import OrderedDict
from dateutil import parser, tz
from enum import Enum
from humanfriendly.terminal.spinners import AutomaticSpinner
from knack.prompting import NoTTYException
from kubernetes import client as k8sClient

from azext_arcdata.kubernetes_sdk.dc.constants import DATA_CONTROLLER_CRD_NAME

# import azext_arcdata.core.deploy as util
import copy
import datetime
import json
import time
import os
import re
import base64
import pathlib
import yaml
import sys
from knack.log import get_logger
from urllib3.exceptions import NewConnectionError, MaxRetryError

from azext_arcdata.kubernetes_sdk.dc.constants import POSTGRES_CRD_NAME

CONNECTION_RETRY_ATTEMPTS = 12
RETRY_INTERVAL = 5

logger = get_logger(__name__)


class progress_state(str, Enum):
    active = "active"
    done = "done"
    failed = "failed"
    pending = "pending"


# ------------------------------------------------------------------------------
# Server Commands
# ------------------------------------------------------------------------------


def postgres_server_arc_create(
    client,
    name,
    path=None,
    namespace=None,
    # replicas=None,
    cores_limit=None,
    cores_request=None,
    memory_limit=None,
    memory_request=None,
    storage_class_data=None,
    storage_class_logs=None,
    storage_class_backups=None,
    volume_claim_mounts=None,
    extensions=None,
    volume_size_data=None,
    volume_size_logs=None,
    volume_size_backups=None,
    workers=None,
    engine_version=DEFAULT_ENGINE_VERSION,
    no_external_endpoint=None,
    # dev=None,
    port=None,
    nowait=False,
    engine_settings=None,
    coordinator_engine_settings=None,
    worker_engine_settings=None,
    use_k8s=None,
):
    """
    Create an Azure Arc enabled PostgreSQL Hyperscale server group.
    :param client:
    :param path: The src filepath of the postgres resource.
    :param name: The name of the Azure Arc enabled PostgreSQL Hyperscale server group.
    :param namespace: Namespace where the Azure Arc enabled PostgreSQL Hyperscale server group is deployed.
    :param replicas: If specified, the instance will deploy the number of replicas, default to 1.
    :param cores_limit: The limit of cores of the managed instance in integer number of vcores.
    :param cores_request: The request for cores of the managed instance in integer number of vcores.
    :param memory_limit: The limit of the capacity of the managed instance in integer amount of memory in GBs.
    :param memory_request: The request for the capacity of the managed instance in integer amount of memory in GBs.
    :param storage_class_data: The storage classes to be used for data persistent volumes.
    :param storage_class_logs: The storage classes to be used for logs persistent volumes.
    :param storage_class_backups: The storage classes to be used for backups persistent volumes.
    :param volume_claim_mounts: A comma-separated list of volume claim mounts.
    :param volume_size_data: The volume size for the storage classes to be used for data.
    :param volume_size_logs: The volume size for the storage classes to be used for logs.
    :param volume_size_backups: The volume size for the storage classes to be used for backups.
    :param extensions: A comma-separated list of Postgres extensions that should be enabled.
    :param workers: The number of worker nodes to provision in a sharded cluster, or zero for single-node Postgres.
    :param no_external_endpoint: If not specified, an external service is created using the same service type as the dc.
    :param dev: If this is specified, then it is considered a dev instance and will not be billed for
    :param port: Optional parameter for the service port.
    :param nowait: If given, the command won't wait until the deployment is ready before returning.
    :param engine_settings: If given, sets the engine properties
    :param coordinator_engine_settings: If given, sets the engine settings on coordinator node
    :param worker_engine_settings: If given, sets the engine settings on worker node
    :return:
    """
    args = locals()
    try:
        if not use_k8s:
            raise ValueError(USE_K8S_EXCEPTION_TEXT)

        check_and_set_kubectl_context()

        # TODO: Support user supplied namespace when the backend supports it
        namespace = namespace or client.namespace

        crd = _get_postgres_crd()

        # Initialize the custom resource's spec
        #
        if not path:
            # If no config file was provided, use this default spec.
            # TODO: Use mutating web hooks to set these default values.
            #
            spec_object = {
                "apiVersion": API_GROUP + "/" + KubernetesClient.get_crd_version(POSTGRES_CRD_NAME),
                "kind": RESOURCE_KIND,
                "metadata": {},
                "spec": {
                    "scheduling": {
                        "default": {
                            "resources": {"requests": {"memory": "256Mi"}}
                        }
                    },
                    "storage": {
                        "data": {"volumes": [{"size": "5Gi"}]},
                        "logs": {"volumes": [{"size": "5Gi"}]},
                        "backups": {"volumes": [{"size": "5Gi"}]},
                    },
                },
            }

        # Otherwise, use the provided src file.
        else:
            spec_object = FileUtil.read_json(path)

        cr = CustomResource.decode(PostgresqlCustomResource, spec_object)
        args["engine_version"] = engine_version
        cr.apply_args(**args)
        cr.metadata.namespace = namespace

        resource_kind_plural = crd.spec.names.plural

        # Temporarily uses env to set dev mode as --dev parameter is disabled
        is_dev = os.environ.get("PG_IS_DEVELOPMENT")
        if is_dev:
            cr.spec.dev = True

        # TODO possibly add this as a post-validation step
        if cr.spec.scale.shards and cr.spec.scale.shards > 0:
            if "citus" not in cr.spec.engine.extensions:
                cr.spec.engine.extensions.insert(0, "citus")

        # TODO possibly add this as a post-validation step
        if cr.spec.scale.replicas and cr.spec.scale.replicas > 1:
            if "citus" not in cr.spec.engine.extensions:
                cr.spec.engine.extensions.insert(0, "citus")

        cr.validate(client.apis.kubernetes)

        custom_object_exists = retry(
            lambda: client.apis.kubernetes.namespaced_custom_object_exists(
                cr.metadata.name,
                cr.metadata.namespace,
                group=API_GROUP,
                version=KubernetesClient.get_crd_version(POSTGRES_CRD_NAME),
                plural=resource_kind_plural,
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

        if custom_object_exists:
            raise ValueError(
                "Postgres Server `{}` already exists in namespace `{}`.".format(
                    name, namespace
                )
            )

        if not no_external_endpoint:
            response = retry(
                lambda: client.apis.kubernetes.list_namespaced_custom_object(
                    namespace,
                    group=ARC_GROUP,
                    version=KubernetesClient.get_crd_version(DATA_CONTROLLER_CRD_NAME),
                    plural=DATA_CONTROLLER_PLURAL,
                ),
                retry_count=CONNECTION_RETRY_ATTEMPTS,
                retry_delay=RETRY_INTERVAL,
                retry_method="list namespaced custom object",
                retry_on_exceptions=(
                    NewConnectionError,
                    MaxRetryError,
                    K8sApiException,
                ),
            )

            dcs = response.get("items")
            if not dcs:
                raise CLIError(
                    "No data controller exists in namespace `{}`. Cannot set external endpoint argument.".format(
                        namespace
                    )
                )
            else:
                is_valid_connectivity_mode(client)
                dc_cr = CustomResource.decode(
                    DataControllerCustomResource, dcs[0]
                )
                cr.spec.services.primary.serviceType = (
                    dc_cr.get_controller_service().serviceType
                )

        secret_name = name + "-login-secret"

        secret_exists = retry(
            lambda: client.apis.kubernetes.secret_exists(
                cr.metadata.namespace, secret_name
            ),
            retry_count=CONNECTION_RETRY_ATTEMPTS,
            retry_delay=RETRY_INTERVAL,
            retry_method="secret exists",
            retry_on_exceptions=(
                NewConnectionError,
                MaxRetryError,
                K8sApiException,
            ),
        )

        if not secret_exists:
            pw = os.environ.get(AZDATA_PASSWORD)
            if not pw:
                if sys.stdin.isatty():
                    pw = prompt_pass(
                        "Postgres Server password:",
                        confirm=True,
                        allow_empty=False,
                    )
                else:
                    raise ValueError(
                        "Please provide a Postgres Server password through the env "
                        "variable AZDATA_PASSWORD."
                    )
            else:
                client.stdout(
                    "Using AZDATA_PASSWORD environment variable for `{}` password.".format(
                        name
                    )
                )

            model = {"secretName": secret_name}
            encoding = "utf-8"
            model["base64Username"] = base64.b64encode(
                bytes("postgres", encoding)
            ).decode(encoding)
            model["base64Password"] = base64.b64encode(
                bytes(pw, encoding)
            ).decode(encoding)
            temp = get_config_from_template(
                os.path.join(
                    os.path.dirname(os.path.realpath(__file__)),
                    "templates",
                    "postgres-login.yaml.tmpl",
                ),
                model,
            )
            postgres_secret = yaml.safe_load(temp)

            retry(
                lambda: client.apis.kubernetes.create_secret(
                    cr.metadata.namespace, postgres_secret, ignore_conflict=True
                ),
                retry_count=CONNECTION_RETRY_ATTEMPTS,
                retry_delay=RETRY_INTERVAL,
                retry_method="create secret",
                retry_on_exceptions=(
                    NewConnectionError,
                    MaxRetryError,
                    K8sApiException,
                ),
            )

        retry(
            lambda: client.apis.kubernetes.create_namespaced_custom_object(
                cr=cr, plural=resource_kind_plural, ignore_conflict=True
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

        if nowait:
            client.stdout(
                "Deployed {0} in namespace `{1}`. "
                "Please use `az postgres arc-server show -n {0} --namespace {1}` to check its status.".format(
                    cr.metadata.name, cr.metadata.namespace
                )
            )
        else:
            response = client.apis.kubernetes.get_namespaced_custom_object(
                cr.metadata.name,
                cr.metadata.namespace,
                group=API_GROUP,
                version=KubernetesClient.get_crd_version(POSTGRES_CRD_NAME),
                plural=resource_kind_plural,
            )
            deployed_cr = CustomResource.decode(
                PostgresqlCustomResource, response
            )

            if not is_windows():
                with AutomaticSpinner(
                    "Deploying {0} in namespace `{1}`".format(
                        cr.metadata.name, cr.metadata.namespace
                    ),
                    show_time=True,
                ):
                    while not _is_instance_ready(deployed_cr):
                        if _is_instance_in_error(deployed_cr):
                            client.stdout(
                                "{0} is in error state:{1}".format(
                                    cr.metadata.name,
                                    _get_error_message(deployed_cr),
                                )
                            )
                            break

                        time.sleep(5)
                        response = retry(
                            lambda: client.apis.kubernetes.get_namespaced_custom_object(
                                cr.metadata.name,
                                cr.metadata.namespace,
                                group=API_GROUP,
                                version=KubernetesClient.get_crd_version(POSTGRES_CRD_NAME),
                                plural=resource_kind_plural,
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
                            PostgresqlCustomResource, response
                        )
                        state = deployed_cr.status.state
                        if state is not None:
                            state = state.lower()
            else:
                client.stdout(
                    "Deploying {0} in namespace `{1}`".format(name, namespace)
                )
                while not _is_instance_ready(deployed_cr):
                    if _is_instance_in_error(deployed_cr):
                        client.stdout(
                            "{0} is in error state:{1}".format(
                                cr.metadata.name,
                                _get_error_message(deployed_cr),
                            )
                        )
                        break

                    time.sleep(5)
                    response = retry(
                        lambda: client.apis.kubernetes.get_namespaced_custom_object(
                            cr.metadata.name,
                            cr.metadata.namespace,
                            group=API_GROUP,
                            version=KubernetesClient.get_crd_version(POSTGRES_CRD_NAME),
                            plural=resource_kind_plural,
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
                        PostgresqlCustomResource, response
                    )
                    state = deployed_cr.status.state
                    if state is not None:
                        state = state.lower()

            if _is_instance_ready(deployed_cr):
                client.stdout("{0} is Ready".format(cr.metadata.name))

    except KubernetesError as e:
        raise CLIError(e.message)
    except Exception as e:
        raise CLIError(e)


def postgres_server_arc_edit(
    client,
    name,
    namespace=None,
    # replicas=None,
    path=None,
    workers=None,
    cores_limit=None,
    cores_request=None,
    memory_limit=None,
    memory_request=None,
    extensions=None,
    # dev=None,
    port=None,
    nowait=False,
    engine_settings=None,
    replace_engine_settings=None,
    coordinator_engine_settings=None,
    worker_engine_settings=None,
    admin_password=False,
    use_k8s=None,
):
    """
    Edit the configuration of an Azure Arc enabled PostgreSQL Hyperscale server group.
    :param client:
    :param name: The name of the Azure Arc enabled PostgreSQL Hyperscale server group you would like to edit.
    :param path: The path to the source json file for the Azure Arc enabled PostgreSQL Hyperscale server group. This is optional.
    :param namespace: Namespace where the Azure Arc enabled PostgreSQL Hyperscale server group is deployed.
    :param replicas: If specified, the instance will deploy the number of replicas
    :param workers: The number of worker nodes to provision in a sharded cluster, or zero for single-node Postgres.
    :param cores_limit: The limit of cores of the managed instance in integer number of vcores.
    :param cores_request: The request for cores of the managed instance in integer number of vcores.
    :param memory_limit: The limit of the capacity of the managed instance in integer amount of memory in GBs.
    :param memory_request: The request for the capacity of the managed instance in integer amount of memory in GBs.
    :param extensions: A comma-separated list of Postgres extensions that should be enabled.
    :param dev: If this is specified, then it is considered a dev instance and will not be billed for.
    :param port: Optional parameter for the service port.
    :param nowait: If given, the command won't wait for the deployment to be ready before returning.
    :param engine_settings: If given, sets the engine properties
    :param replace_engine_settings: If given, replaces all existing engine settings
    :param coordinator_engine_settings: If given, sets the engine settings on coordinator node
    :param worker_engine_settings: If given, sets the engine settings on worker node
    :param admin_password: The admin password for Postgres.
    :return:
    """
    args = locals()
    try:
        if not use_k8s:
            raise ValueError(USE_K8S_EXCEPTION_TEXT)
        check_and_set_kubectl_context()

        # TODO: Support user supplied namespace when the backend supports it
        namespace = namespace or client.namespace

        # Get the Postgres resource
        old_cr, crd = _get_postgres_custom_object(client, name, namespace)
        if old_cr is None:
            raise CLIError(
                "Azure Arc enabled PostgreSQL Hyperscale server "
                "group {} not found.".format(name)
            )

        if path:
            # Load the spec from a file if provided
            body = FileUtil.read_json(path)
        else:
            # Otherwise clone the existing resource so we can validate against it
            body = copy.deepcopy(old_cr.encode())

        cr = CustomResource.decode(PostgresqlCustomResource, body)
        cr.apply_args(**args)

        # TODO possibly add this as a post-validation step
        if cr.spec.scale.shards and cr.spec.scale.shards > 0:
            if "citus" not in cr.spec.engine.extensions:
                cr.spec.engine.extensions.insert(0, "citus")

        # Run validations that examine multiple custom resource properties
        #
        cr.validate(client.apis.kubernetes)

        # TODO: Validations on the spec should happen on the backend.
        # Until we have webhook validation configured, we'll do them here.
        # https://sqlhelsinki.visualstudio.com/aris/_workitems/edit/16349
        if cr.spec.scale.replicas and old_cr.spec.scale.replicas:
            if cr.spec.scale.replicas < old_cr.spec.scale.replicas:
                raise CLIError("The number of replicas cannot be decreased.")

        # TODO: Validations on the spec should happen on the backend.
        # Until we have webhook validation configured, we'll do them here.
        # https://sqlhelsinki.visualstudio.com/aris/_workitems/edit/16349
        if cr.spec.scale.replicas == 0:
            raise CLIError("The number of replicas cannot be zero.")

        # TODO possibly add this as a post-validation step
        if cr.spec.scale.replicas and cr.spec.scale.replicas > 1:
            if "citus" not in cr.spec.engine.extensions:
                cr.spec.engine.extensions.insert(0, "citus")

        # Update the admin password if requested
        if admin_password:
            pw = os.environ.get(AZDATA_PASSWORD)
            if not pw:
                if sys.stdin.isatty():
                    pw = prompt_pass(
                        "Postgres Server password:",
                        confirm=True,
                        allow_empty=False,
                    )
                else:
                    raise ValueError(
                        "Please provide a Postgres Server password "
                        "through the AZDATA_PASSWORD environment variable."
                    )

            client.stdout("Updating password")
            client.apis.kubernetes.patch_secret(
                namespace,
                name + "-login-secret",
                {"stringData": {"password": pw}},
            )

        # Replace CR
        client.apis.kubernetes.replace_namespaced_custom_object(
            cr=cr, plural=crd.plural
        )

        if nowait:
            client.stdout(
                "Updated {0} in namespace `{1}`. "
                "Please use `az postgres arc-server show -n {0} --namespace {1}` to check its status.".format(
                    cr.metadata.name, cr.metadata.namespace
                )
            )
        else:
            response = client.apis.kubernetes.get_namespaced_custom_object(
                cr.metadata.name,
                cr.metadata.namespace,
                group=API_GROUP,
                version=KubernetesClient.get_crd_version(POSTGRES_CRD_NAME),
                plural=crd.plural,
            )
            deployed_cr = CustomResource.decode(
                PostgresqlCustomResource, response
            )

            if not is_windows():
                with AutomaticSpinner(
                    "Updating {0} in namespace `{1}`".format(
                        cr.metadata.name, cr.metadata.namespace
                    ),
                    show_time=True,
                ):
                    while not _is_instance_ready(deployed_cr):
                        if _is_instance_in_error(deployed_cr):
                            client.stdout(
                                "{0} is in error state:{1}".format(
                                    cr.metadata.name,
                                    _get_error_message(deployed_cr),
                                )
                            )
                            break

                        time.sleep(5)
                        response = (
                            client.apis.kubernetes.get_namespaced_custom_object(
                                cr.metadata.name,
                                cr.metadata.namespace,
                                group=API_GROUP,
                                version=KubernetesClient.get_crd_version(POSTGRES_CRD_NAME),
                                plural=crd.plural,
                            )
                        )
                        deployed_cr = CustomResource.decode(
                            PostgresqlCustomResource, response
                        )

            else:
                client.stdout(
                    "Updating {0} in namespace `{1}`".format(name, namespace)
                )
                while not _is_instance_ready(deployed_cr):
                    if _is_instance_in_error(deployed_cr):
                        client.stdout(
                            "{0} is in error state:{1}".format(
                                cr.metadata.name,
                                _get_error_message(deployed_cr),
                            )
                        )
                        break

                    time.sleep(5)
                    response = (
                        client.apis.kubernetes.get_namespaced_custom_object(
                            cr.metadata.name,
                            cr.metadata.namespace,
                            group=API_GROUP,
                            version=KubernetesClient.get_crd_version(POSTGRES_CRD_NAME),
                            plural=crd.plural,
                        )
                    )
                    deployed_cr = CustomResource.decode(
                        PostgresqlCustomResource, response
                    )

            if _is_instance_ready(deployed_cr):
                client.stdout("{0} is Ready".format(cr.metadata.name))

    except KubernetesError as e:
        raise CLIError(e.message)
    except Exception as e:
        raise CLIError(e)


def postgres_server_arc_delete(
    client, name, namespace=None, force=False, use_k8s=None
):
    """
    Delete an Azure Arc enabled PostgreSQL Hyperscale server group.
    :param client:
    :param name: Name of the Azure Arc enabled PostgreSQL Hyperscale server group..
    :param force: A boolean indicating whether to delete the Azure Arc enabled PostgreSQL Hyperscale server group without confirmation.
    :return:
    """
    try:
        if not use_k8s:
            raise ValueError(USE_K8S_EXCEPTION_TEXT)
        check_and_set_kubectl_context()

        is_valid_connectivity_mode(client)

        # TODO: Support user supplied namespace when the backend supports it
        namespace = namespace or client.namespace

        cr, crd = _get_postgres_custom_object(client, name, namespace)
        if cr is None:
            raise CLIError(
                "Azure Arc enabled PostgreSQL Hyperscale server group {} not found.".format(
                    name
                )
            )

        try:
            yes = force or prompt_y_n(
                "Do you want to delete Azure Arc enabled PostgreSQL Hyperscale server group {}?".format(
                    name
                )
            )
        except NoTTYException:
            raise CLIError("Please specify --force in non-interactive mode.")

        if not yes:
            client.stdout(
                "Azure Arc enabled PostgreSQL Hyperscale server group {} not deleted.".format(
                    name
                )
            )
            return

        client.apis.kubernetes.delete_namespaced_custom_object(
            name=name, namespace=namespace, crd=crd
        )

        client.stdout(
            "Deleted Azure Arc enabled PostgreSQL Hyperscale server group {} from namespace {}".format(
                name, namespace
            )
        )

        client.stdout(
            "Note: Deleting a server group does not remove its associated storage. Reach out to your Kubernetes administrator or "
            + 'read documentation article "Delete an Azure Arc enabled PostgreSQL Hyperscale server group" for possible next steps.'
        )

    except KubernetesError as e:
        raise CLIError(e.message)
    except Exception as e:
        raise CLIError(e)


def postgres_server_arc_show(
    client, name, namespace=None, path=None, use_k8s=None
):
    """
    Show the details of an Azure Arc enabled PostgreSQL Hyperscale server group.
    :param client:
    :param name: Name of the Azure Arc enabled PostgreSQL Hyperscale server group.
    :param path: A path to a json file where the full specification for the Azure Arc enabled PostgreSQL Hyperscale server group should be written.
    :return:
    """
    try:
        if not use_k8s:
            raise ValueError(USE_K8S_EXCEPTION_TEXT)
        check_and_set_kubectl_context()

        # TODO: Support user supplied namespace when the backend supports it
        namespace = namespace or client.namespace

        (cr, _) = _get_postgres_custom_object(client, name, namespace, raw=True)
        if cr is None:
            raise CLIError(
                "Azure Arc enabled PostgreSQL Hyperscale server group {} not found.".format(
                    name
                )
            )

        if path:
            if not os.path.isdir(path):
                os.makedirs(path)
            path = os.path.join(path, "{}.json".format(name))
            with open(path, "w") as outfile:
                json.dump(cr, outfile, indent=4)
            client.stdout("{0} specification written to {1}".format(name, path))
        else:
            return cr

    except KubernetesError as e:
        raise CLIError(e.message)
    except Exception as e:
        raise CLIError(e)


def postgres_server_arc_list(client, namespace=None, use_k8s=None):
    """
    List Azure Arc enabled PostgreSQL Hyperscale server groups.
    :param client:
    :return:
    """
    try:
        if not use_k8s:
            raise ValueError(USE_K8S_EXCEPTION_TEXT)
        check_and_set_kubectl_context()

        crd = _get_postgres_crd()

        # TODO: Support user supplied namespace when the backend supports it
        namespace = namespace or client.namespace

        response = client.apis.kubernetes.list_namespaced_custom_object(
            namespace,
            group=API_GROUP,
            version=KubernetesClient.get_crd_version(POSTGRES_CRD_NAME),
            plural=crd.spec.names.plural,
        )
        # Temporary, need to discuss with PMs what standardized output we"d like for all partners
        items = response.get("items")

        result = []
        items.sort(key=lambda i: i["kind"] + "\n" + i["metadata"]["name"])
        for item in items:
            cr = CustomResource.decode(PostgresqlCustomResource, item)
            result.append(
                {
                    "name": cr.metadata.name,
                    "workers": cr.spec.scale.shards,  # defaults to 0
                    "replicas": cr.spec.scale.replicas,  # defaults to 1
                    "state": cr.status.state,
                }
            )

        return result

    except KubernetesError as e:
        raise CLIError(e.message)
    except Exception as e:
        raise CLIError(e)


def arc_postgres_endpoint_list(client, name=None, namespace=None, use_k8s=None):
    """
    List Azure Arc enabled PostgreSQL Hyperscale server groups.
    :param client:
    :param name: Name of the Azure Arc enabled PostgreSQL Hyperscale server group.
    :return:
    """
    try:
        if not use_k8s:
            raise ValueError(USE_K8S_EXCEPTION_TEXT)
        check_and_set_kubectl_context()

        # TODO: Support user supplied namespace when the backend supports it
        namespace = namespace or client.namespace

        custom_resources = []

        if name:
            (cr, _) = _get_postgres_custom_object(client, name, namespace)
            if cr is None:
                raise CLIError(
                    "Azure Arc enabled PostgreSQL Hyperscale server group {} not found.".format(
                        name
                    )
                )
            custom_resources.append(cr)
        else:
            crd = _get_postgres_crd()

            response = client.apis.kubernetes.list_namespaced_custom_object(
                namespace,
                group=API_GROUP,
                version=KubernetesClient.get_crd_version(POSTGRES_CRD_NAME),
                plural=crd.spec.names.plural,
            )
            items = response.get("items")

            for item in items:
                cr = CustomResource.decode(PostgresqlCustomResource, item)
                if cr:
                    custom_resources.append(cr)

        arc_postgres_endpoints = {"namespace": namespace}
        instances = []

        # Loop through the specified custom resources and retrieve their endpoints from their status
        for cr in custom_resources:
            endpoints = []

            if cr.status:
                descrip_str = "description"
                endpoint_str = "endpoint"

                # Connection string
                ext_endpoint = cr.status.primaryEndpoint
                if ext_endpoint:
                    connection_str = "postgresql://postgres:<replace with password>@{}".format(
                        ext_endpoint
                    )
                else:
                    connection_str = "Not yet available"
                endpoints.append(
                    {
                        descrip_str: "PostgreSQL Instance",
                        endpoint_str: connection_str,
                    }
                )

                # Logs
                logs_endpoint = cr.status.log_search_dashboard
                endpoints.append(
                    {
                        descrip_str: "Log Search Dashboard",
                        endpoint_str: logs_endpoint,
                    }
                )

                # Metrics
                metrics_endpoint = cr.status.metrics_dashboard
                endpoints.append(
                    {
                        descrip_str: "Metrics Dashboard",
                        endpoint_str: metrics_endpoint,
                    }
                )

            instances.append(
                {
                    "name": cr.metadata.name,
                    "engine": cr.kind,
                    "endpoints": endpoints,
                }
            )

        arc_postgres_endpoints["instances"] = instances

        return arc_postgres_endpoints

    except KubernetesError as e:
        raise CLIError(e.message)
    except Exception as e:
        raise CLIError(e)


# def postgres_server_arc_config_init(client, path, engine_version=None):
#     """
#     Returns a package of crd.json and spec-template.json.
#     :param client:
#     :param path:
#     :return:
#     """
#     try:
#         if not os.path.isdir(path):
#             os.makedirs(path, exist_ok=True)

#         if not is_windows():
#             with AutomaticSpinner("Fetching {0} template".format(RESOURCE_KIND),
#                                   show_time=True):
#                 crd_response = client.apis.controller.resource_crd_get(RESOURCE_KIND)
#                 spec_response = client.apis.controller.resource_spec_get(RESOURCE_KIND)
#         else:
#             crd_response = client.apis.controller.resource_crd_get(RESOURCE_KIND)
#             spec_response = client.apis.controller.resource_spec_get(RESOURCE_KIND)

#         crd_pretty = json.dumps(crd_response, indent=4)
#         spec_pretty = json.dumps(spec_response, indent=4)

#         with open(os.path.join(path, "crd.json"), "w") as output:
#             output.write(crd_pretty)

#         with open(os.path.join(path, "spec.json"), "w") as output:
#             output.write(spec_pretty)

#         client.stdout("{0} template created in directory: {1}".format(RESOURCE_KIND, path))

#     except Exception as e:
#         raise CLIError(e)


# def postgres_server_arc_config_add(client, path, json_values):
#     """
#     Add new key and value to the given config file
#     :param client:
#     :param path:
#     :param json_values:
#     :return:
#     """
#     try:
#         config_object = DeploymentConfigUtil.config_add(path, json_values)
#         DeploymentConfigUtil.write_config_file(path, config_object)
#     except Exception as e:
#         raise CLIError(e)


# def postgres_server_arc_config_replace(client, path, json_values):
#     """
#     Replace the value of a given key in the given config file
#     :param client:
#     :param path:
#     :param json_values:
#     :return:
#     """
#     try:
#         config_object = DeploymentConfigUtil.config_replace(path, json_values)
#         DeploymentConfigUtil.write_config_file(path, config_object)
#     except Exception as e:
#         raise CLIError(e)


# def postgres_server_arc_config_remove(client, path, json_path):
#     """
#     Remove a key from the given config file
#     :param client:
#     :param path:
#     :param json_path:
#     :return:
#     """
#     try:
#         config_object = DeploymentConfigUtil.config_remove(path, json_path)
#         DeploymentConfigUtil.write_config_file(path, config_object)
#     except Exception as e:
#         raise CLIError(e)


# def postgres_server_arc_config_patch(client, path, patch_file):
#     """
#     Patch a given file against the given config file
#     :param client:
#     :param path:
#     :param patch_file:
#     :return:
#     """
#     try:
#         config_object = DeploymentConfigUtil.config_patch(path, patch_file)
#         DeploymentConfigUtil.write_config_file(path, config_object)
#     except Exception as e:
#         raise CLIError(e)


def _get_postgres_crd():
    """
    Returns the postgresql CRD.
    :return:
    """
    api = k8sClient.ApiextensionsV1Api()
    crds = api.list_custom_resource_definition()
    for crd in crds.items:
        if crd.spec.names.kind == RESOURCE_KIND:
            return crd
    raise CLIError("Unable to locate PostgreSQL custom resource definition.")


def _get_postgres_custom_object(client, name, namespace, raw=False):
    """
    Returns the custom object and the corresponding CRD as a tuple for the Azure Arc enabled PostgreSQL Hyperscale server group identified by name and engine version.
    It's possible to create multipe Azure Arc enabled PostgreSQL Hyperscale server groups with the same name but different engine version.
    Name and engine version can uniquely identify an Azure Arc enabled PostgreSQL Hyperscale server group in a namespace.
    :param client:
    :param name: The name of the instance.
    :param namespace: Namespace where the Azure Arc enabled PostgreSQL Hyperscale server group is deployed.
    :param raw: If True this function does not decode the json into a custom resource and returns the raw json instead
    :return: None will be returned if the Azure Arc enabled PostgreSQL Hyperscale server group cannot be found.
             CLIError will be raised if there are multiple Azure Arc enabled PostgreSQL Hyperscale server groups found.
    """

    crd = CustomResourceDefinition(_get_postgres_crd().to_dict())

    try:
        result = client.apis.kubernetes.get_namespaced_custom_object(
            name=name, namespace=namespace, crd=crd
        )
        cr = CustomResource.decode(PostgresqlCustomResource, result)
        return (result if raw else cr), crd
    except K8sApiException as e:
        if e.status == http_status_codes.not_found:
            pass
    return None, None


def _wait_for_backup_state_change(func, *funcargs, **kwargs):
    delay = kwargs.get("delay", 5)
    while True:
        time.sleep(delay)
        result = func(*funcargs)
        if result.progress.lower() not in (
            progress_state.active,
            progress_state.pending,
        ):
            break
        delay *= 2
        if delay > 60:
            delay = 60
    return result


def _parse_restore_time(time):
    if (
        re.match(r"^(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)[mMhHdDwW]$", time)
        is not None
    ):
        return time
    else:
        t = parser.parse(time)
        if t.tzinfo is None:
            t = datetime.datetime(
                t.year,
                t.month,
                t.day,
                t.hour,
                t.minute,
                t.second,
                t.microsecond,
                tz.tzlocal(),
            )
        return t.astimezone(tz.tzutc())


def _is_instance_ready(cr):
    return cr.metadata.generation == cr.status.observed_generation and (
        cr.status.state is not None and cr.status.state.lower() == "ready"
    )


def _is_instance_in_error(cr):
    """
    Check that the SQL Mi instance is in error state
    :param cr: Instance to check the readiness of
    :return: True if the instance is in error, False otherwise
    """
    return cr.status.state is not None and cr.status.state.lower() == "error"


def _get_error_message(cr):
    """
    Get error message from the status of custom resource
    :param cr: Instance to get error message.
    """
    return cr.status.message
