# ------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# ------------------------------------------------------------------------------

from .azure.azure_resource_client import AzureResourceClient
from azext_arcdata.dc import data_controller_properties
from azext_arcdata.dc.azure import constants as azure_constants
from azext_arcdata.dc.constants import (
    TEMPLATE_DIR,
    CONTROLLER_LABEL,
    CONTROLLER_SVC,
    DIRECT,
    ARC_WEBHOOK_JOB_TEMPLATE,
    ARC_WEBHOOK_ROLE_TEMPLATE,
    ARC_WEBHOOK_RB_TEMPLATE,
    ARC_WEBHOOK_CR_TEMPLATE,
    ARC_WEBHOOK_CRB_TEMPLATE,
    ARC_WEBHOOK_SA_TEMPLATE,
    POSTGRES_CRD,
    SQLMI_CRD,
    MONITOR_CRD,
    MONITOR_CRD_VERSION,
    MONITOR_PLURAL,
    MONITOR_RESOURCE,
)
from azext_arcdata.kubernetes_sdk.models import (
    CustomResourceDefinition,
    MonitorCustomResource,
)
from azext_arcdata.core.cli_client import CliClient
from azext_arcdata.core.constants import (
    ARC_NAMESPACE_LABEL,
    ARC_WEBHOOK_PREFIX,
    AZDATA_PASSWORD,
    AZDATA_USERNAME,
    DOMAIN_SERVICE_ACCOUNT_USERNAME,
    DOMAIN_SERVICE_ACCOUNT_PASSWORD,
    DOCKER_USERNAME,
    DOCKER_PASSWORD,
    REGISTRY_USERNAME,
    REGISTRY_PASSWORD,
)
from azext_arcdata.core.constants import (
    ARC_GROUP,
    DATA_CONTROLLER_CRD_VERSION,
    DATA_CONTROLLER_PLURAL,
)
from azext_arcdata.core.util import (
    display,
    get_config_from_template,
    retry,
    check_and_set_kubectl_context,
)
from azext_arcdata.kubernetes_sdk.models.data_controller_custom_resource import (
    DataControllerCustomResource,
    CustomResource,
)
from azext_arcdata.kubernetes_sdk.client import (
    KubernetesError,
    http_status_codes,
)
from urllib3.exceptions import NewConnectionError, MaxRetryError
from requests.exceptions import ConnectionError
from kubernetes.client.rest import ApiException as K8sApiException
from kubernetes import client as k8sClient
from http import HTTPStatus
from datetime import datetime, timedelta
from knack.log import get_logger
from knack.cli import CLIError
from types import SimpleNamespace

import azext_arcdata.core.kubernetes as kubernetes_util
import time
import os
import yaml
import base64
import pydash as _

CONNECTION_RETRY_ATTEMPTS = 12
DELETE_CLUSTER_TIMEOUT_SECONDS = 300
RETRY_INTERVAL = 5
UPDATE_INTERVAL = (15 * 60) / RETRY_INTERVAL
SCRIPT_PATH = os.path.dirname(os.path.realpath(__file__))

logger = get_logger(__name__)


def beget(az_cli, kwargs):
    """Client factory"""
    return DataCtrClientMixin(az_cli, namespace=kwargs.get("namespace"))


def beget_no_namespace(az_cli, _):
    """Client factory - no check on namespace"""
    return DataCtrClientMixin(az_cli, check_namespace=False)


class DataCtrClientMixin(CliClient):
    def __init__(self, az_cli, namespace=None, check_namespace=True):
        super(DataCtrClientMixin, self).__init__(
            az_cli, namespace=namespace, check_namespace=check_namespace
        )
        self.cluster_name = None
        self._azure_resource_client = AzureResourceClient()

    @property
    def subscription(self):
        """
        Gets the Azure subscription.
        """

        # Gets the azure subscription by attempting to gather it from:
        # 1. global argument [--subscription] if provided
        # 2. Otherwise active subscription in profile if available
        # 3. Otherwise `None`
        subscription = self.az_cli.data.get("subscription_id")

        if not subscription:
            try:
                subscription = self.profile.get_subscription_id()
            except CLIError:
                subscription = None
        else:
            try:
                subscription = self.profile.get_subscription(
                    subscription=subscription
                ).get("id")
            except CLIError:
                logger.warning("To not see this warning, first login to Azure.")

        return subscription

    @property
    def azure_resource_client(self):
        return self._azure_resource_client

    def dc_create(self, crd: dict, cr: DataControllerCustomResource):
        """
        Create a data controller
        """
        # Set up the private registry if the docker environment variables set
        #
        if (
            os.environ.get(DOCKER_USERNAME) and os.environ.get(DOCKER_PASSWORD)
        ) or (
            os.environ.get(REGISTRY_USERNAME)
            and os.environ.get(REGISTRY_PASSWORD)
        ):
            retry(
                lambda: kubernetes_util.setup_private_registry(
                    cr.metadata.namespace,
                    cr.spec.docker.registry,
                    secret_name=cr.spec.credentials.dockerRegistry,
                    ignore_conflict=True,
                ),
                retry_count=CONNECTION_RETRY_ATTEMPTS,
                retry_delay=RETRY_INTERVAL,
                retry_method="set up docker private registry",
                retry_on_exceptions=(NewConnectionError, MaxRetryError),
            )

        # Create the bootstrapper, if it needs to be created
        #
        retry(
            lambda: self.create_bootstrapper(cr),
            retry_count=CONNECTION_RETRY_ATTEMPTS,
            retry_delay=RETRY_INTERVAL,
            retry_method="create bootstrapper",
            retry_on_exceptions=(
                NewConnectionError,
                MaxRetryError,
                KubernetesError,
            ),
        )

        retry(
            lambda: self.apis.kubernetes.create_namespaced_custom_object(
                cr=cr, plural=crd.plural, ignore_conflict=True
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

        i = 0

        # Check if the external controller service exists
        #
        while not retry(
            lambda: self.apis.kubernetes.service_ready(
                cr.metadata.namespace, CONTROLLER_SVC
            ),
            retry_count=CONNECTION_RETRY_ATTEMPTS,
            retry_delay=RETRY_INTERVAL,
            retry_method="service ready",
            retry_on_exceptions=(NewConnectionError, MaxRetryError),
        ):
            # Log to console once every 5 minutes if controller service is
            # not ready
            #
            if i != 0 and i % 60 == 0:
                display(
                    "Waiting for data controller service to be ready after %d "
                    "minutes." % ((i * RETRY_INTERVAL) / 60)
                )

            time.sleep(RETRY_INTERVAL)
            i = i + 1

        # Check if controller is running
        #
        while not retry(
            lambda: self.apis.kubernetes.pod_is_running(
                cr.metadata.namespace, CONTROLLER_LABEL
            ),
            retry_count=CONNECTION_RETRY_ATTEMPTS,
            retry_delay=RETRY_INTERVAL,
            retry_method="pod is running",
            retry_on_exceptions=(
                NewConnectionError,
                MaxRetryError,
                K8sApiException,
            ),
        ):
            # Log to console once every 5 minutes if controller is not running
            #
            if i != 0 and i % 60 == 0:
                display(
                    "Waiting for data controller to be running after %d "
                    "minutes." % ((i * RETRY_INTERVAL) / 60)
                )

            time.sleep(RETRY_INTERVAL)
            i = i + 1

        service = retry(
            lambda: self.apis.kubernetes.get_service(
                cr.metadata.namespace, CONTROLLER_SVC
            ),
            retry_count=CONNECTION_RETRY_ATTEMPTS,
            retry_delay=RETRY_INTERVAL,
            retry_method="get service",
            retry_on_exceptions=(
                NewConnectionError,
                MaxRetryError,
                K8sApiException,
            ),
        )

        controller_endpoint = retry(
            lambda: self.apis.kubernetes.get_service_endpoint(
                cr.metadata.namespace, service
            ),
            retry_count=CONNECTION_RETRY_ATTEMPTS,
            retry_delay=RETRY_INTERVAL,
            retry_method="get service endpoint",
            retry_on_exceptions=(
                NewConnectionError,
                MaxRetryError,
                K8sApiException,
            ),
        )

        ip_endpoint = retry(
            lambda: self.apis.kubernetes.get_service_endpoint(
                cr.metadata.namespace, service, True
            ),
            retry_count=CONNECTION_RETRY_ATTEMPTS,
            retry_delay=RETRY_INTERVAL,
            retry_method="get service endpoint",
            retry_on_exceptions=(
                NewConnectionError,
                MaxRetryError,
                K8sApiException,
            ),
        )

        if controller_endpoint == ip_endpoint:
            endpoint_str = controller_endpoint
        else:
            endpoint_str = controller_endpoint + ", " + ip_endpoint

        display(
            "Data controller endpoint is available at {}".format(endpoint_str)
        )

        response = retry(
            lambda: self.apis.kubernetes.get_namespaced_custom_object(
                cr.metadata.name,
                cr.metadata.namespace,
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

        self._create_webhook_job(deployed_cr)

        return response, deployed_cr

    def monitor_deployment_status(self, monitor_cr):
        """
        Check monitor custom resource status during deployment
        """
        with open(MONITOR_CRD, "r") as stream:
            temp = yaml.safe_load(stream)
            monitor_crd = CustomResourceDefinition(temp)

        response = self.apis.kubernetes.get_namespaced_custom_object(
            monitor_cr.metadata.name,
            monitor_cr.metadata.namespace,
            group=ARC_GROUP,
            version=MONITOR_CRD_VERSION,
            plural=monitor_crd.plural,
        )
        deployed_cr = CustomResource.decode(MonitorCustomResource, response)

        while not kubernetes_util.is_instance_ready(deployed_cr):
            time.sleep(5)
            response = retry(
                lambda: self.apis.kubernetes.get_namespaced_custom_object(
                    monitor_cr.metadata.name,
                    monitor_cr.metadata.namespace,
                    group=ARC_GROUP,
                    version=MONITOR_CRD_VERSION,
                    plural=monitor_crd.plural,
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

            deployed_cr = CustomResource.decode(MonitorCustomResource, response)

    def monitor_endpoint_list(client, namespace, endpoint_name=None):
        """
        List endpoints for the Monitor CR.
        """
        try:
            check_and_set_kubectl_context()

            # namespace = client.profile.active_context.namespace

            response = client.apis.kubernetes.get_namespaced_custom_object(
                MONITOR_RESOURCE,
                namespace,
                group=ARC_GROUP,
                version=MONITOR_CRD_VERSION,
                plural=MONITOR_PLURAL,
            )
            cr = CustomResource.decode(MonitorCustomResource, response)
            if cr is None:
                raise CLIError("Monitor custom resource not found.")

            endpoints = []

            if cr.status:
                descrip_str = "description"
                endpoint_str = "endpoint"
                name_str = "name"
                protocol_str = "protocol"

                # Logs
                logs_endpoint = {
                    descrip_str: "Log Search Dashboard",
                    endpoint_str: cr.status.log_search_dashboard,
                    name_str: "logsui",
                    protocol_str: "https",
                }

                # Metrics
                metrics_endpoint = {
                    descrip_str: "Metrics Dashboard",
                    endpoint_str: cr.status.metrics_dashboard,
                    name_str: "metricsui",
                    protocol_str: "https",
                }

                if endpoint_name is None:
                    endpoints.append(logs_endpoint)
                    endpoints.append(metrics_endpoint)
                    return endpoints
                elif endpoint_name.lower().startswith("metricsui"):
                    return metrics_endpoint
                else:
                    return logs_endpoint

        except KubernetesError as e:
            raise CLIError(e.message)
        except Exception as e:
            raise CLIError(e)

    def _create_webhook_job(self, dc_cr: DataControllerCustomResource):
        """
        Creates the webhook job for creating webhook resources registering
        the webhook
        """
        namespace = dc_cr.metadata.namespace
        docker = dc_cr.spec.docker
        imagePullSecret = dc_cr.spec.credentials.dockerRegistry
        if os.environ.get("BOOTSTRAPPER_IMAGE"):
            bootstrapper = os.environ["BOOTSTRAPPER_IMAGE"]
        else:
            bootstrapper = "{0}/{1}/arc-bootstrapper:{2}".format(
                docker.registry, docker.repository, docker.imageTag
            )

        config_model = SimpleNamespace(
            namespace=namespace,
            bootstrapper=bootstrapper,
            imagePullSecret=imagePullSecret,
        )

        # Create service account
        #
        config = get_config_from_template(ARC_WEBHOOK_SA_TEMPLATE, config_model)
        spec_obj = yaml.safe_load(config)
        retry(
            lambda: self.apis.kubernetes.create_namespaced_service_account(
                namespace, spec_obj
            ),
            retry_count=CONNECTION_RETRY_ATTEMPTS,
            retry_delay=RETRY_INTERVAL,
            retry_method="create namespaced service account",
            retry_on_exceptions=(
                NewConnectionError,
                MaxRetryError,
                K8sApiException,
            ),
        )

        # Create cluster role
        #
        config = get_config_from_template(
            ARC_WEBHOOK_CR_TEMPLATE, config_model
        )
        spec_obj = yaml.safe_load(config)
        retry(
            lambda: kubernetes_util.update_cluster_role(
                spec_obj["metadata"]["name"], spec_obj
            ),
            retry_count=CONNECTION_RETRY_ATTEMPTS,
            retry_delay=RETRY_INTERVAL,
            retry_method="create cluster role",
            retry_on_exceptions=(
                NewConnectionError,
                MaxRetryError,
                K8sApiException,
            ),
        )

        # Create cluster role binding
        #
        config = get_config_from_template(
            ARC_WEBHOOK_CRB_TEMPLATE, config_model
        )
        spec_obj = yaml.safe_load(config)
        retry(
            lambda: kubernetes_util.update_cluster_role_binding(
                spec_obj["metadata"]["name"], spec_obj
            ),
            retry_count=CONNECTION_RETRY_ATTEMPTS,
            retry_delay=RETRY_INTERVAL,
            retry_method="create cluster role binding",
            retry_on_exceptions=(
                NewConnectionError,
                MaxRetryError,
                K8sApiException,
            ),
        )

        # Create role binding
        #
        config = get_config_from_template(
            ARC_WEBHOOK_RB_TEMPLATE, config_model
        )
        spec_obj = yaml.safe_load(config)
        retry(
            lambda: self.apis.kubernetes.create_namespaced_role_binding(
                spec_obj["metadata"]["namespace"], spec_obj
            ),
            retry_count=CONNECTION_RETRY_ATTEMPTS,
            retry_delay=RETRY_INTERVAL,
            retry_method="create role binding",
            retry_on_exceptions=(
                NewConnectionError,
                MaxRetryError,
                K8sApiException,
            ),
        )

        # Create role
        #
        config = get_config_from_template(
            ARC_WEBHOOK_ROLE_TEMPLATE, config_model
        )
        spec_obj = yaml.safe_load(config)
        retry(
            lambda: self.apis.kubernetes.create_namespaced_role(
                spec_obj["metadata"]["namespace"], spec_obj
            ),
            retry_count=CONNECTION_RETRY_ATTEMPTS,
            retry_delay=RETRY_INTERVAL,
            retry_method="create role",
            retry_on_exceptions=(
                NewConnectionError,
                MaxRetryError,
                K8sApiException,
            ),
        )

        # Create job
        #
        config = get_config_from_template(
            ARC_WEBHOOK_JOB_TEMPLATE, config_model
        )
        spec_obj = yaml.safe_load(config)
        retry(
            lambda: self.apis.kubernetes.create_namespaced_job(
                namespace, spec_obj
            ),
            retry_count=CONNECTION_RETRY_ATTEMPTS,
            retry_delay=RETRY_INTERVAL,
            retry_method="create cluster role binding",
            retry_on_exceptions=(
                NewConnectionError,
                MaxRetryError,
                K8sApiException,
            ),
        )

    def create_cluster_role_for_monitoring(
        self, dc_cr: DataControllerCustomResource, namespace
    ):
        """
        Create a cluster role for monitoring
        """
        # Create cluster role with read permission on the pod/node resources
        #
        if (
            dc_cr.spec.security is None
            or getattr(dc_cr.spec.security, "allowPodMetricsCollection", None)
            is None
            or dc_cr.spec.security.allowPodMetricsCollection
        ):

            service_account_name = "sa-arc-metricsdc-reader"
            cluster_role_name = namespace + ":cr-arc-metricsdc-reader"
            cluster_role_binding_name = namespace + ":crb-arc-metricsdc-reader"
            try:
                body = yaml.safe_load(
                    get_config_from_template(
                        os.path.join(
                            SCRIPT_PATH,
                            "./templates",
                            "clusterrole-metricsdc-reader.yaml",
                        ),
                        cluster_role_name,
                    )
                )
                kubernetes_util.update_cluster_role(cluster_role_name, body)

                body = k8sClient.V1ClusterRoleBinding(
                    metadata=k8sClient.V1ObjectMeta(
                        name=cluster_role_binding_name
                    ),
                    subjects=[
                        k8sClient.V1Subject(
                            kind="ServiceAccount",
                            name=service_account_name,
                            namespace=namespace,
                        )
                    ],
                    role_ref=k8sClient.V1RoleRef(
                        kind="ClusterRole",
                        name=cluster_role_name,
                        api_group="rbac.authorization.k8s.io",
                    ),
                )
                kubernetes_util.update_cluster_role_binding(
                    cluster_role_binding_name, body
                )

            except K8sApiException as e:
                # Telegraf requires the cluster wide role for the pod
                # collection. The az might not have sufficient permissions to
                # create the ClusterRole and ClusterRoleBinding for telegraf.
                # If so, only print the warning message and keep on deployment.
                # The pod metrics will not be collected, but can be resumed
                # automatically if the cluster role gets created at anytime.
                #
                logger.warning(e.body)
                logger.warning(
                    "The current user does not have sufficient permissions to "
                    "create '%s' ClusterRole and '%s' ClusterRoleBinding. "
                    + "If these resources already exist, please ignore this "
                    "warning. Otherwise please ask your cluster "
                    "administrator "
                    "to manually create them to enable the pod metrics "
                    "monitoring. More details: "
                    "https://aka.ms/arcdata_k8s_native",
                    cluster_role_name,
                    cluster_role_binding_name,
                )
                pass

    def create_bootstrapper(self, cr):
        """
        Check if the bootstrapper exists in the given namespace.
        If the bootstrapper does not exist, deploy it.
        """

        try:
            model = dict()
            model["namespace"] = cr.metadata.namespace
            ns = cr.metadata.namespace
            docker = cr.spec.docker

            if not self.apis.kubernetes.replica_set_exists(ns, "bootstrapper"):
                if os.environ.get("BOOTSTRAPPER_IMAGE"):
                    model["bootstrapper"] = os.environ["BOOTSTRAPPER_IMAGE"]
                else:
                    model[
                        "bootstrapper"
                    ] = "{0}/{1}/arc-bootstrapper:{2}".format(
                        docker.registry, docker.repository, docker.imageTag
                    )
                model["imagePullPolicy"] = docker.imagePullPolicy
                model["imagePullSecret"] = cr.spec.credentials.dockerRegistry
                config = get_config_from_template(
                    os.path.join(TEMPLATE_DIR, "rs-bootstrapper.yaml.tmpl"),
                    model,
                )
                rs = yaml.safe_load(config)
                self.apis.kubernetes.create_replica_set(ns, rs)

            if not self.apis.kubernetes.namespaced_role_exists(
                ns, "role-bootstrapper"
            ):
                config = get_config_from_template(
                    os.path.join(TEMPLATE_DIR, "role-bootstrapper.yaml.tmpl"),
                    model,
                )
                role = yaml.safe_load(config)
                self.apis.kubernetes.create_namespaced_role(ns, role)

            if not self.apis.kubernetes.namespaced_role_binding_exists(
                ns, "rb-bootstrapper"
            ):
                config = get_config_from_template(
                    os.path.join(TEMPLATE_DIR, "rb-bootstrapper.yaml.tmpl"),
                    model,
                )
                rb = yaml.safe_load(config)
                self.apis.kubernetes.create_namespaced_role_binding(ns, rb)

            if not self.apis.kubernetes.service_account_exists(
                ns, "sa-arc-bootstrapper"
            ):
                config = get_config_from_template(
                    os.path.join(TEMPLATE_DIR, "sa-arc-bootstrapper.yaml.tmpl"),
                    model,
                )
                sa = yaml.safe_load(config)
                self.apis.kubernetes.create_namespaced_service_account(ns, sa)

            if not self.apis.kubernetes.secret_exists(
                ns, "controller-login-secret"
            ):
                #######
                import sys
                from azext_arcdata.core.util import (
                    read_environment_variables,
                    check_environment_variables,
                )
                from azext_arcdata.dc.constants import ARC_NAME

                display("The kubernetes secret is not available, creating now.")

                if sys.stdin.isatty():
                    read_environment_variables(ARC_NAME, True)
                else:
                    check_environment_variables(ARC_NAME)
                #######
                model[AZDATA_USERNAME] = base64.b64encode(
                    bytes(os.environ[AZDATA_USERNAME], "utf-8")
                ).decode("utf-8")
                model[AZDATA_PASSWORD] = base64.b64encode(
                    bytes(os.environ[AZDATA_PASSWORD], "utf-8")
                ).decode("utf-8")
                config = get_config_from_template(
                    os.path.join(
                        TEMPLATE_DIR, "controller-login-secret.yaml.tmpl"
                    ),
                    model,
                )
                secret = yaml.safe_load(config)
                self.apis.kubernetes.create_secret(ns, secret)

            connectivity_mode = cr.spec.settings["azure"][
                data_controller_properties.CONNECTION_MODE
            ].lower()
            if (
                connectivity_mode == DIRECT
                and not self.apis.kubernetes.secret_exists(
                    ns, "upload-service-principal-secret"
                )
            ):
                model["SPN_CLIENT_ID"] = base64.b64encode(
                    bytes(os.environ["SPN_CLIENT_ID"], "utf-8")
                ).decode("utf-8")
                model["SPN_CLIENT_SECRET"] = base64.b64encode(
                    bytes(os.environ["SPN_CLIENT_SECRET"], "utf-8")
                ).decode("utf-8")
                model["SPN_TENANT_ID"] = base64.b64encode(
                    bytes(os.environ["SPN_TENANT_ID"], "utf-8")
                ).decode("utf-8")
                model["SPN_AUTHORITY"] = base64.b64encode(
                    bytes(os.environ["SPN_AUTHORITY"], "utf-8")
                ).decode("utf-8")
                config = get_config_from_template(
                    os.path.join(
                        TEMPLATE_DIR,
                        "secret-upload-service-principal.yaml.tmpl",
                    ),
                    model,
                )
                secret = yaml.safe_load(config)
                self.apis.kubernetes.create_secret(ns, secret)

            # If domain service account is provided through environment and
            # active directory mode is
            # enabled in spec, create a secret for domain service account.
            #
            if (
                DOMAIN_SERVICE_ACCOUNT_USERNAME in os.environ
                and DOMAIN_SERVICE_ACCOUNT_PASSWORD in os.environ
                and getattr(cr.spec, "security", None) is not None
                and getattr(cr.spec.security, "activeDirectory", None)
                is not None
                and not self.apis.kubernetes.secret_exists(
                    ns, "domain-service-account-secret"
                )
            ):
                model[DOMAIN_SERVICE_ACCOUNT_USERNAME] = base64.b64encode(
                    bytes(os.environ[DOMAIN_SERVICE_ACCOUNT_USERNAME], "utf-8")
                ).decode("utf-8")
                model[DOMAIN_SERVICE_ACCOUNT_PASSWORD] = base64.b64encode(
                    bytes(os.environ[DOMAIN_SERVICE_ACCOUNT_PASSWORD], "utf-8")
                ).decode("utf-8")
                config = get_config_from_template(
                    os.path.join(
                        TEMPLATE_DIR, "domain-service-account-secret.yaml.tmpl"
                    ),
                    model,
                )
                secret = yaml.safe_load(config)
                self.apis.kubernetes.create_secret(ns, secret)

        except K8sApiException as e:
            raise KubernetesError(e)

    def dc_delete(self, namespace, name):
        """
        Delete a data controller.
        """
        if not retry(
            kubernetes_util.namespace_exists,
            namespace,
            retry_count=CONNECTION_RETRY_ATTEMPTS,
            retry_delay=RETRY_INTERVAL,
            retry_method="check if namespace exists",
            retry_on_exceptions=(NewConnectionError, MaxRetryError),
        ):
            display("Namespace '%s' doesn't exist" % namespace)
            return

        # Try to delete the cluster
        #
        i = 1
        resources_are_deleted = False
        http_status = None
        cluster_is_empty = False
        while not cluster_is_empty:

            time.sleep(RETRY_INTERVAL)

            if not resources_are_deleted:
                #  Try to delete the remaining resources in the cluster
                #
                (resources_are_deleted, http_status) = retry(
                    kubernetes_util.delete_cluster_resources,
                    namespace,
                    retry_count=CONNECTION_RETRY_ATTEMPTS,
                    retry_delay=RETRY_INTERVAL,
                    retry_method="delete cluster resources",
                    retry_on_exceptions=(NewConnectionError, MaxRetryError),
                )
                #  Try to delete the bootstrapper
                #
                retry(
                    kubernetes_util.delete_cluster_resources,
                    namespace,
                    "app=bootstrapper",
                    retry_count=CONNECTION_RETRY_ATTEMPTS,
                    retry_delay=RETRY_INTERVAL,
                    retry_method="delete cluster resources",
                    retry_on_exceptions=(NewConnectionError, MaxRetryError),
                )

                if http_status == HTTPStatus.FORBIDDEN:
                    break

            # Check if the cluster is empty
            #
            cluster_is_empty = retry(
                kubernetes_util.namespace_is_empty,
                namespace,
                retry_count=CONNECTION_RETRY_ATTEMPTS,
                retry_delay=RETRY_INTERVAL,
                retry_method="namespace is empty",
                retry_on_exceptions=(NewConnectionError, MaxRetryError),
            )

            if i * RETRY_INTERVAL > DELETE_CLUSTER_TIMEOUT_SECONDS:
                logger.warn(
                    "Data controller is not empty after %d minutes."
                    % (DELETE_CLUSTER_TIMEOUT_SECONDS / 60)
                )
                break

            i = i + 1
            time.sleep(RETRY_INTERVAL)

        if not cluster_is_empty:
            raise Exception("Failed to delete data controller.")

    def get_data_controller(self, cluster_name):
        """
        Get data control
        """
        self.cluster_name = cluster_name

        data_controller_list = retry(
            lambda: self.apis.kubernetes.list_namespaced_custom_object(
                namespace=cluster_name,
                group=ARC_GROUP,
                version=DATA_CONTROLLER_CRD_VERSION,
                plural=DATA_CONTROLLER_PLURAL,
            ),
            retry_count=CONNECTION_RETRY_ATTEMPTS,
            retry_delay=RETRY_INTERVAL,
            retry_method="get namespaced custom object",
            retry_on_exceptions=(NewConnectionError, MaxRetryError),
        )

        data_controller_cr = None

        # Kubernetes will not block the creation of more than one datacontroller
        # in a namespace. To prevent multiple datacontrollers from being
        # deployed in the same namespace, we update the state for any
        # datacontrollers deployed after the first to state "duplicateerror". To
        # avoid using the incorrect datacontroller custom resource, search for
        # the instance that is not in an error state.
        for data_controller in data_controller_list["items"]:
            if (
                data_controller["status"]["state"] != ""
                and data_controller["status"]["state"].lower()
                != "duplicateerror"
            ):
                data_controller_cr = data_controller
                break

        dc_settings = data_controller_cr["spec"]["settings"]
        return {
            "instanceName": dc_settings["controller"][
                data_controller_properties.DISPLAY_NAME
            ],
            "instanceNamespace": self.cluster_name,
            "kind": azure_constants.RESOURCE_KIND_DATA_CONTROLLER,
            "subscriptionId": dc_settings["azure"][
                data_controller_properties.SUBSCRIPTION
            ],
            "resourceGroupName": dc_settings["azure"][
                data_controller_properties.RESOURCE_GROUP
            ],
            "location": dc_settings["azure"][
                data_controller_properties.LOCATION
            ],
            "connectionMode": dc_settings["azure"][
                data_controller_properties.CONNECTION_MODE
            ],
            "infrastructure": data_controller_cr["spec"]["infrastructure"],
            "publicKey": "",
            "k8sRaw": data_controller_cr,
            "infrastructure": _.get(data_controller_cr, "spec.infrastructure"),
        }

    def list_all_custom_resource_instances(self, cluster_name):
        """
        list all custom resource instances
        """
        result = []
        crd_files = [POSTGRES_CRD, SQLMI_CRD]

        for crd_file in crd_files:
            # Create the control plane CRD if it doesn't already exist
            with open(crd_file, "r") as stream:
                temp = yaml.safe_load(stream)
                crd = CustomResourceDefinition(temp)

                try:
                    response = (
                        self.apis.kubernetes.list_namespaced_custom_object(
                            cluster_name, crd=crd
                        )
                    )
                except K8sApiException as e:
                    if e.status == http_status_codes.not_found:
                        # CRD has not been applied yet, because no custom
                        # resource of this kind has been created yet
                        continue
                    else:
                        raise e

                for item in response["items"]:
                    spec = item["spec"]
                    status = item["status"] if "status" in item else None

                    if (
                        status
                        and "state" in status
                        and status["state"].lower() == "ready"
                    ):
                        result.append(
                            {
                                "kind": item["kind"],
                                "instanceName": item["metadata"]["name"],
                                "instanceNamespace": item["metadata"][
                                    "namespace"
                                ],
                                "creationTimestamp": item["metadata"][
                                    "creationTimestamp"
                                ],
                                "externalEndpoint": status["externalEndpoint"]
                                if "externalEndpoint" in status
                                else "-",
                                "vcores": str(spec["limits"]["vcores"])
                                if "limits" in spec
                                and "vcores" in spec["limits"]
                                else "-",
                                "k8sRaw": item,
                            }
                        )

        return result

    def get_dc_azure_resource(self, data_controller):
        """
        Get a shadow resource for the data controller.
        """
        response = retry(
            lambda: self.azure_resource_client.get_azure_resource(
                resource_name=data_controller["instanceName"],
                instance_type="dataControllers",
                subscription_id=data_controller["subscriptionId"],
                resource_group_name=data_controller["resourceGroupName"],
            ),
            retry_count=CONNECTION_RETRY_ATTEMPTS,
            retry_delay=RETRY_INTERVAL,
            retry_method="get Azure data controller",
            retry_on_exceptions=(
                ConnectionError,
                NewConnectionError,
                MaxRetryError,
            ),
        )

        # no data controller was returned
        if response is True:
            return None

        return response

    def create_dc_azure_resource(self, data_controller):
        """
        Create a shadow resource for the data controller.
        """
        retry(
            lambda: self.azure_resource_client.create_azure_data_controller(
                uid=data_controller["k8sRaw"]["metadata"]["uid"],
                resource_name=data_controller["instanceName"],
                subscription_id=data_controller["subscriptionId"],
                resource_group_name=data_controller["resourceGroupName"],
                location=data_controller["location"],
                public_key=data_controller["publicKey"],
                extended_properties={
                    "k8sRaw": _.get(data_controller, "k8sRaw"),
                    "infrastructure": _.get(data_controller, "infrastructure"),
                },
            ),
            retry_count=CONNECTION_RETRY_ATTEMPTS,
            retry_delay=RETRY_INTERVAL,
            retry_method="create Azure data controller",
            retry_on_exceptions=(
                ConnectionError,
                NewConnectionError,
                MaxRetryError,
            ),
        )

    def create_azure_resource(self, resource, data_controller):
        """
        Create a shadow resource for custom resource.
        """
        retry(
            lambda: self.azure_resource_client.create_azure_resource(
                instance_type=azure_constants.RESOURCE_TYPE_FOR_KIND[
                    resource["kind"]
                ],
                data_controller_name=data_controller["instanceName"],
                resource_name=resource["instanceName"],
                subscription_id=data_controller["subscriptionId"],
                resource_group_name=data_controller["resourceGroupName"],
                location=data_controller["location"],
                extended_properties={"k8sRaw": _.get(resource, "k8sRaw")},
            ),
            retry_count=CONNECTION_RETRY_ATTEMPTS,
            retry_delay=RETRY_INTERVAL,
            retry_method="create Azure resource",
            retry_on_exceptions=(
                ConnectionError,
                NewConnectionError,
                MaxRetryError,
            ),
        )

    def delete_azure_resource(self, resource, data_controller):
        """
        Delete the shadow resource for custom resource.
        """
        resource_name = resource["instanceName"]
        instance_type = azure_constants.RESOURCE_TYPE_FOR_KIND[resource["kind"]]
        subscription_id = data_controller["subscriptionId"]
        resource_group_name = data_controller["resourceGroupName"]

        retry(
            self.azure_resource_client.delete_azure_resource,
            resource_name,
            instance_type,
            subscription_id,
            resource_group_name,
            retry_count=CONNECTION_RETRY_ATTEMPTS,
            retry_delay=RETRY_INTERVAL,
            retry_method="delete Azure resource",
            retry_on_exceptions=(
                ConnectionError,
                NewConnectionError,
                MaxRetryError,
            ),
        )

    def calculate_usage(self, namespace, exclude_curr_period):
        """
        request_body = {
            "namespace": namespace,
            "excludeCurrentPeriod": exclude_curr_period,
        }

        return self.apis.controller.usage_calculate_post(body=request_body)
        """
        pass

    def upload_usages_dps(
        self, data_controller, usage, timestamp, correlation_vector
    ):
        import zlib
        import base64
        import json

        uncompressed_usage = json.loads(
            str(
                zlib.decompress(
                    base64.b64decode(usage["usages"]), -zlib.MAX_WBITS
                ),
                "utf-8",
            )
        )

        return self.azure_resource_client.upload_usages_dps(
            cluster_id=data_controller["k8sRaw"]["metadata"]["uid"],
            correlation_vector=correlation_vector,
            name=data_controller["instanceName"],
            subscription_id=data_controller["subscriptionId"],
            resource_group_name=data_controller["resourceGroupName"],
            location=data_controller["location"],
            connection_mode=data_controller["connectionMode"],
            infrastructure=data_controller["infrastructure"],
            timestamp=timestamp,
            usages=uncompressed_usage,
            signature=usage["signature"],
        )

    def create_cluster_role_for_data_controller(self, namespace):
        """
        Create a cluster role for data controller
        :param namespace:
        :return:
        """
        # Create cluster role with read permission on the CRDs
        #

        service_account_name = "sa-arc-controller"
        cluster_role_name = namespace + ":cr-arc-dc-watch"
        cluster_role_binding_name = namespace + ":crb-arc-dc-watch"
        try:
            body = yaml.safe_load(
                get_config_from_template(
                    os.path.join(
                        SCRIPT_PATH, "./templates", "clusterrole-dc-watch.yaml"
                    ),
                    cluster_role_name,
                )
            )
            kubernetes_util.update_cluster_role(cluster_role_name, body)

            body = k8sClient.V1ClusterRoleBinding(
                metadata=k8sClient.V1ObjectMeta(name=cluster_role_binding_name),
                subjects=[
                    k8sClient.V1Subject(
                        kind="ServiceAccount",
                        name=service_account_name,
                        namespace=namespace,
                    )
                ],
                role_ref=k8sClient.V1RoleRef(
                    kind="ClusterRole",
                    name=cluster_role_name,
                    api_group="rbac.authorization.k8s.io",
                ),
            )
            kubernetes_util.update_cluster_role_binding(
                cluster_role_binding_name, body
            )

        except K8sApiException as e:
            # Data controller requires cluster role to watch CRDs.
            #
            logger.warning(e.body)
            logger.warning(
                "The current user does not have sufficient permissions to "
                "create '%s' ClusterRole and '%s' ClusterRoleBinding. "
                + "If these resources already exist, please ignore this warning. "
                "Otherwise please ask your cluster administrator "
                "to manually create them. More details: https://aka.ms/arcdata"
                "_k8s_native",
                cluster_role_name,
                cluster_role_binding_name,
            )
            pass
