# ------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# ------------------------------------------------------------------------------

from .swagger_1_0_0 import AzureArcDataManagementClient
from ._util import dict_to_dot_notation, wait, retry, wait_for_error
from knack.log import get_logger
from collections import namedtuple

import azure.core.exceptions as exceptions
import json
import time
import requests
import os

__all__ = ["arm_clients"]

logger = get_logger(__name__)


def arm_clients(subscription, credential):
    c = {
        "dc": DataControllerClient(subscription, credential),
        "hydration": HydrationClient(subscription, credential),
    }

    return namedtuple("CommandValueObject", " ".join(list(c.keys())))(**c)


# ============================================================================ #
# ============================================================================ #
# ============================================================================ #


class BaseClient(object):
    def __init__(self, subscription, credential):
        self._subscription = subscription
        self._mgmt_client = AzureArcDataManagementClient(
            credential=credential,
            subscription_id=subscription,
        )
        self._session = requests.Session()
        self._session.headers.update(
            {
                "Authorization": "Bearer {}".format(
                    credential.get_token().token
                ),
                "Content-Type": "application/json",
            }
        )
        self.MGMT_URL = (
            f"https://management.azure.com/subscriptions/{self._subscription}"
        )

    @property
    def subscription(self):
        return self._subscription


# ============================================================================ #
# ============================================================================ #
# ============================================================================ #


class HydrationClient(BaseClient):
    RESOURCE_HYDRATION_API_VERSION = "2021-08-31-preview"

    def __init__(self, subscription, credential):
        super(HydrationClient, self).__init__(subscription, credential)

    def get_sync_rules(self, resource_group, custom_location):
        """
        Gets all resource sync rules of a custom location
        """
        try:
            url = (
                f"{self.MGMT_URL}"
                f"/resourceGroups/{resource_group}"
                f"/providers/Microsoft.ExtendedLocation"
                f"/customLocations/{custom_location}"
                f"/resourceSyncRules"
                f"?api-version={self.RESOURCE_HYDRATION_API_VERSION}"
            )
            res = self._session.get(url=url)
            logger.debug(res.status_code)
            logger.debug(res.text)
            res = res.json().get("value") or []
            return res
        except exceptions.HttpResponseError as e:
            logger.debug(e)
            raise exceptions.HttpResponseError(e.message)

    def has_hydration(self, resource_group, custom_location):
        """
        Indicates if a resource hydration has already been created on the
        provided `custom_location`.
        """

        def _is_valid_priority(properties):
            priority = properties.priority
            return priority == 100

        def _is_valid_match_labels(properties):
            label = properties.selector.matchLabels.to_dict.get(
                "management.azure.com/resourceProvider"
            )
            return label and label == "Microsoft.AzureArcData"

        def _is_valid_target_resource_group(properties):
            return (
                properties.targetResourceGroup
                == f"/subscriptions/{self.subscription}"
                f"/resourceGroups/{resource_group}"
            )

        # TODO: remove check when no longer in preview-only
        from azext_arcdata.core.constants import FEATURE_FLAG_RESOURCE_SYNC

        if os.getenv(FEATURE_FLAG_RESOURCE_SYNC) not in ["1", "on", "true"]:
            return True

        for rule in self.get_sync_rules(resource_group, custom_location):
            p = dict_to_dot_notation(rule).properties
            if (
                _is_valid_priority(p)
                and _is_valid_match_labels(p)
                and _is_valid_target_resource_group(p)
            ):
                logger.debug("Hydration rule exists.")
                return True

        return False


# ============================================================================ #
# ============================================================================ #
# ============================================================================ #


class DataControllerClient(BaseClient):
    API_VERSION_MAP = dict_to_dot_notation(
        {
            "CONNECTED_CLUSTER": "2021-10-01",
            "ARC_DATA_SERVICES_EXTENSION": "2021-09-01",
            "ROLE_ASSIGNMENT": "2018-09-01-preview",
        }
    )

    def __init__(self, subscription, credential):
        super(DataControllerClient, self).__init__(subscription, credential)

    def create(self, name, resource_group, arm_tmpl, polling=True):
        url = (
            f"{self.MGMT_URL}"
            f"/resourceGroups/{resource_group}"
            f"/providers/Microsoft.Resources"
            f"/deployments/{name}?api-version=2020-06-01"
        )

        logger.debug(url)
        response = self._session.put(url=url, json=arm_tmpl)
        logger.debug(response.text)
        logger.debug(response.status_code)

        if not response.ok:
            raise Exception(response.reason)

        return self._deployment_wait(name, resource_group) if polling else {}

    def get(self, name, resource_group):
        try:
            result = self._mgmt_client.data_controllers.get_data_controller(
                resource_group_name=resource_group,
                data_controller_name=name,
            )

            logger.debug(json.dumps(result.as_dict(), indent=4))

            return result
        except exceptions.HttpResponseError as e:
            logger.debug(e)
            message = e.message.split("Message: ")[-1]
            raise exceptions.HttpResponseError(message)
        except Exception as e:
            raise e

    def delete(self, name, resource_group, polling=True):
        try:
            self._mgmt_client.data_controllers.begin_delete_data_controller(
                resource_group_name=resource_group,
                data_controller_name=name,
                polling=polling,
            )

            if polling:
                wait_for_error(
                    self.get,
                    name,
                    resource_group,
                    e=exceptions.HttpResponseError,
                )
        except exceptions.HttpResponseError as e:
            logger.debug(e)
            raise exceptions.HttpResponseError(e.message)
        except Exception as e:
            raise e

    def list(self, resource_group):
        try:
            result = self._mgmt_client.data_controllers.list_in_group(
                resource_group
            )

            return result
        except exceptions.HttpResponseError as e:
            logger.debug(e)
            raise exceptions.HttpResponseError(e.message)
        except Exception as e:
            raise e

    def patch(self, name, resource_group, properties: dict):
        try:
            result = self._mgmt_client.data_controllers.patch_data_controller(
                resource_group_name=resource_group,
                data_controller_name=name,
                data_controller_resource=properties,
            )

            return result
        except exceptions.HttpResponseError as e:
            logger.debug(e)
            raise exceptions.HttpResponseError(e.message)
        except Exception as e:
            raise e

    def upgrade(
        self,
        name,
        resource_group,
        target,
        dry_run=False,
        polling=True,
    ):
        from .swagger_1_0_0.models import DataControllerResource

        def _dc_upgrade_completed():
            get_result = self.get(name, resource_group).properties.k8_s_raw

            return _.get(get_result, ".status.state", False) == "Ready"

        try:
            dc = self.get(name, resource_group)

            # We cannot initiate a new PUT request if a previous request is
            # still in the Accepted state.
            #
            if dc.properties.provisioning_state == "Accepted":
                raise Exception(
                    "An existing operation is in progress. Please check your "
                    "DC's status in the Azure Portal."
                )

            # if dry_run is specified, we will simply print and return.
            if dry_run:
                print("****Dry Run****")
                print(
                    "Arcdata Control Plane would be upgraded to: {0}".format(
                        target
                    )
                )
                return

            dc.properties.k8_s_raw["spec"]["docker"]["imageTag"] = target

            data_controller_resource = DataControllerResource(
                location=dc.location,
                extended_location=dc.extended_location,
                properties=dc.properties,
            )

            result = (
                self._mgmt_client.data_controllers.begin_put_data_controller(
                    resource_group_name=resource_group,
                    data_controller_name=name,
                    data_controller_resource=data_controller_resource,
                    polling=polling,
                )
            )

            # Wait for the operation to be accepted
            #
            for _ in range(0, 60, 5):
                dc = self.get(name, resource_group)
                if dc.properties.provisioning_state != "Accepted":
                    break
                else:
                    time.sleep(5)

            if dc.properties.provisioning_state == "Failed":
                raise Exception(
                    "DC upgrade failed. Please check your DC's status in the "
                    "Azure Portal for more information"
                )

            if polling:
                # Setting a total wait time of 600 sec with a step of 5 sec
                for _ in range(0, 600, 5):
                    if _dc_upgrade_completed():
                        break
                    else:
                        time.sleep(5)

                if not _dc_upgrade_completed():
                    raise Exception(
                        "DC upgrade failed. Please check your DC's status in "
                        "the Azure Portal for more information."
                    )
            else:
                return result
        except exceptions.HttpResponseError as e:
            logger.debug(e)
            raise exceptions.HttpResponseError(e.message)
        except Exception as e:
            raise e

    def get_connected_cluster_location(self, cluster_name, resource_group):
        cluster = self.get_connected_cluster(cluster_name, resource_group)
        return cluster["location"]

    def get_connected_cluster(self, cluster_name, resource_group):
        try:
            url = (
                f"{self.MGMT_URL}/resourceGroups/{resource_group}"
                f"/providers/Microsoft.Kubernetes"
                f"/connectedClusters"
                f"?api-version={self.API_VERSION_MAP.CONNECTED_CLUSTER}"
            )

            logger.debug(url)
            response = self._session.get(url=url)

            if (
                response.status_code == 404
                or len(response.json()["value"]) == 0
            ):
                raise Exception(
                    f"No connected cluster was found under the resource group "
                    f"{resource_group}. Create a connected cluster first."
                )
            else:
                connected_clusters = response.json()
                for resource in connected_clusters["value"]:
                    if cluster_name == resource["name"]:
                        # log cluster properties
                        for key, value in resource["properties"].items():
                            if key != "agentPublicKeyCertificate":
                                logger.debug(f"{key} = {value}")
                        logger.debug(f"location = {resource['location']}")
                        return resource

                raise Exception(
                    f"The cluster {cluster_name} was not found in the resource "
                    f"group {resource_group}."
                )
        except exceptions.HttpResponseError as e:
            logger.debug(e)
            raise exceptions.HttpResponseError(e.message)
        except Exception as e:
            raise e

    def get_extensions(self, cluster_name, resource_group):
        try:
            url = (
                "{url}/resourceGroups/{resource_group}/providers"
                "/Microsoft.Kubernetes/connectedClusters/{cluster_name}"
                "/providers/Microsoft.KubernetesConfiguration/extensions"
                "?api-version={version}".format(
                    url=self.MGMT_URL,
                    resource_group=resource_group,
                    cluster_name=cluster_name,
                    version=self.API_VERSION_MAP.ARC_DATA_SERVICES_EXTENSION,
                )
            )

            logger.debug(url)
            response = self._session.get(url=url)
            if response.status_code == 404:
                raise exceptions.HttpResponseError(
                    "404 error while calling: {}".format(url)
                )
            else:
                return response.json()
        except exceptions.HttpResponseError as e:
            logger.debug(e)
            raise exceptions.HttpResponseError(e.message)
        except Exception as e:
            raise e

    def get_role_assignments(self, cluster_name, resource_group):
        try:
            extension = self.get_extensions(cluster_name, resource_group)
            url = (
                "{url}/resourceGroups/{resource_group}/providers/"
                "Microsoft.Authorization/roleAssignments?"
                "api-version={version}&%24filter=assignedTo(%27{id}%27)".format(
                    url=self.MGMT_URL,
                    resource_group=resource_group,
                    version=self.API_VERSION_MAP.ROLE_ASSIGNMENT,
                    id=extension["value"][0]["identity"]["principalId"],
                )
            )

            logger.debug(url)
            response = self._session.get(url=url)
            if response.status_code == 404:
                raise exceptions.HttpResponseError(
                    "404 error while calling: {}".format(url)
                )
            else:
                return response.json()
        except exceptions.HttpResponseError as e:
            logger.debug(e)
            raise exceptions.HttpResponseError(e.message)
        except Exception as e:
            raise e

    def resolve_namespace(
        self, namespace, custom_location, cluster_name, resource_group
    ):
        ext = self.get_extensions(cluster_name, resource_group)

        if len(ext["value"]) == 0:
            # No CL yet so just make namespace == CL or use the one provided
            namespace = namespace or custom_location
        else:
            # use the namespace defined in the existing CL
            logger.debug(json.dumps(ext, indent=4))
            ext = dict_to_dot_notation(ext["value"][0])
            ext_namespace = ext.properties.scope.cluster.releaseNamespace

            if namespace and namespace != ext_namespace:
                raise ValueError(
                    f"The namespace provided {namespace} "
                    f"does not match the namespace {ext_namespace}"
                    f" in the existing custom location "
                    f"{custom_location}."
                )
            else:
                namespace = ext_namespace

        return namespace

    def get_resource_graph(self, cluster_name, resource_group, namespace):
        try:
            url = (
                "https://management.azure.com/providers/Microsoft."
                "ResourceGraph/resources?api-version=2021-03-01"
            )

            logger.debug(url)
            query = "\
                resources\
                | where subscriptionId =~ '{subscriptionId}'\
                | where resourceGroup == '{resourceGroup}'\
                | where type =~ 'microsoft.kubernetes/connectedclusters'\
                | where properties.provisioningState =~ 'succeeded'\
                | where name == '{cluster}'\
                | project clusterId=id, subscriptionId, clusterName=name\
                | join kind=leftouter (kubernetesconfigurationresources\
                    | where subscriptionId =~ '{subscriptionId}'\
                    | where resourceGroup == '{resourceGroup}'\
                    | where type =~ 'microsoft.kubernetesconfiguration/extensions'\
                    | where properties.ExtensionType =~ 'microsoft.arcdataservices'\
                    | where (properties.ProvisioningState =~ 'succeeded' or properties.InstallState =~ 'installed')\
                    | project extensionId=id, subscriptionId, namespace=properties.Scope.cluster.ReleaseNamespace)\
                on $left.subscriptionId == $right.subscriptionId\
                | where extensionId contains clusterId\
                | extend namespace=tostring(namespace)\
                | where namespace =~ '{namespace}'\
                | join (resources\
                    | where subscriptionId =~ '{subscriptionId}'\
                    | where resourceGroup == '{resourceGroup}'\
                    | where type =~ 'microsoft.extendedLocation/customLocations'\
                    | where properties.provisioningState =~ 'succeeded'\
                    | extend hostClusterId = tostring(properties.hostResourceId)\
                    | extend namespace = tostring(properties.namespace)\
                    | project hostClusterId, customLocationName=name, namespace)\
                on $left.clusterId == $right.hostClusterId and $left.namespace == $right.namespace\
                | project clusterName, namespace, customLocationName\
            ".format(
                subscriptionId=self.subscription,
                resourceGroup=resource_group,
                cluster=cluster_name,
                namespace=namespace,
            )

            payload = {"subscriptions": [self.subscription], "query": query}
            payload = json.dumps(payload, indent=4)

            response = self._session.post(url=url, data=payload).json()
            logger.debug(json.dumps(response, indent=4))
            return response
        except exceptions.HttpResponseError as e:
            logger.debug(e)
            raise exceptions.HttpResponseError(e.message)
        except Exception as e:
            raise e

    def _deployment_wait(self, name, resource_group):
        def _dc_deployment_completed():
            result = retry(
                self.get,
                name,
                resource_group,
                max_tries=200,
                e=exceptions.HttpResponseError,
            )

            if (
                result
                and result.properties
                and result.properties.k8_s_raw
                and "status" in result.properties.k8_s_raw
                and "state" in result.properties.k8_s_raw["status"]
            ):
                return result.properties.k8_s_raw["status"]["state"]
            else:
                # Status is unknown, so we we continue to wait.
                return None

        # Setting a total wait time of 1800 sec with a step of 5 sec
        wait(_dc_deployment_completed)
        if _dc_deployment_completed() != "Ready":
            raise Exception(
                "DC deployment failed. Please check your dc status in portal \
                or reset this create process."
            )
        return self.get(name, resource_group)

    def __create_depreciated_dc__(
        self,
        resource_group,
        name,
        location,
        custom_location,
        connectivity_mode,
        path=None,
        storage_class=None,
        infrastructure=None,
        auto_upload_metrics=None,
        auto_upload_logs=None,
        polling=True,
    ):
        from azext_arcdata.core.env import Env
        from azext_arcdata.core.prompt import prompt_assert
        from .swagger_1_0_0.models import (
            DataControllerResource,
            DataControllerProperties,
            ExtendedLocation,
            BasicLoginInformation,
        )

        try:
            # -- check existing dc to void dc recreate --
            all_dcs = self.list_dc(resource_group)
            dc_name_list = []
            for curr_dc in all_dcs:
                dc_name_list.append(curr_dc.as_dict()["name"])
            if name in dc_name_list:
                # Cannot do dc_put for the same dc now since it will break
                # the status key in dc_get response
                #
                raise Exception(
                    "A Data Controller {name} has already been created.".format(
                        name=name
                    )
                )

            config_file = os.path.join(path, "control.json")
            logger.debug("Configuration profile: %s", config_file)

            with open(config_file, encoding="utf-8") as input_file:
                k8s = json.load(input_file)
                logger.debug(json.dumps(k8s, indent=4))

            # -- docker property overrides --
            if os.getenv("CONTROLLER_REGISTRY"):
                k8s["spec"]["docker"]["registry"] = os.getenv(
                    "CONTROLLER_REGISTRY"
                )

            if os.getenv("CONTROLLER_REPOSITORY"):
                k8s["spec"]["docker"]["repository"] = os.getenv(
                    "CONTROLLER_REPOSITORY"
                )

            if os.getenv("CONTROLLER_IMAGE_TAG"):
                k8s["spec"]["docker"]["imageTag"] = os.getenv(
                    "CONTROLLER_IMAGE_TAG"
                )

            if auto_upload_metrics is not None:
                # Grant the contributor role logic after this line. TBD
                # Grant the matrixs publisher role logic after this line. TBD
                k8s["spec"]["settings"]["azure"][
                    "autoUploadMetrics"
                ] = auto_upload_metrics

            if auto_upload_logs is not None:
                # Read the log work space info after this line. TBD
                k8s["spec"]["settings"]["azure"][
                    "autoUploadLogs"
                ] = auto_upload_logs

            if infrastructure:
                k8s["spec"]["infrastructure"] = infrastructure
            elif not k8s["spec"]["infrastructure"]:
                k8s["spec"]["infrastructure"] = "onpremises"
            infrastructure = k8s["spec"]["infrastructure"]

            if storage_class:
                k8s["spec"]["storage"]["data"]["className"] = storage_class
                k8s["spec"]["storage"]["logs"]["className"] = storage_class

            if (
                not k8s["spec"]["storage"]["data"]["className"]
                or not k8s["spec"]["storage"]["logs"]["className"]
            ):
                storage_class = prompt_assert("Storage class: ")
                k8s["spec"]["storage"]["data"]["className"] = storage_class
                k8s["spec"]["storage"]["logs"]["className"] = storage_class

            # Populate the arm request body
            k8s["spec"]["settings"]["controller"]["displayName"] = name
            k8s["spec"]["settings"]["azure"][
                "connectionMode"
            ] = connectivity_mode
            k8s["spec"]["settings"]["azure"]["location"] = location
            k8s["spec"]["settings"]["azure"]["resourceGroup"] = resource_group
            k8s["spec"]["settings"]["azure"][
                "subscription"
            ] = self._subscription
            k8s["spec"]["credentials"][
                "controllerAdmin"
            ] = "controller-login-secret"

            # -- extended-location --
            extended_location = ExtendedLocation(
                name=(
                    "/subscriptions/"
                    + self._subscription
                    + "/resourcegroups/"
                    + resource_group
                    + "/providers/microsoft.extendedlocation/customlocations/"
                    + custom_location
                ),
                type="CustomLocation",
            )

            # -- properties --
            cred = Env.get_log_and_metrics_credentials()
            metrics_dashboard_credential = BasicLoginInformation(
                username=cred.metrics_username, password=cred.metrics_password
            )
            logs_dashboard_credential = BasicLoginInformation(
                username=cred.log_username, password=cred.log_password
            )
            properties = DataControllerProperties(
                infrastructure=infrastructure,
                k8_s_raw=k8s,
                metrics_dashboard_credential=metrics_dashboard_credential,
                logs_dashboard_credential=logs_dashboard_credential,
            )
            data_controller_resource = DataControllerResource(
                location=location,
                extended_location=extended_location,
                properties=properties,
            )

            # -- log --
            d = data_controller_resource.as_dict().copy()
            d["properties"]["metrics_dashboard_credential"]["password"] = "*"
            d["properties"]["logs_dashboard_credential"]["password"] = "*"

            logger.debug("<DataControllerResource>")
            logger.debug(json.dumps(d, indent=4))

            result = (
                self._mgmt_client.data_controllers.begin_put_data_controller(
                    resource_group_name=resource_group,
                    data_controller_name=name,
                    data_controller_resource=data_controller_resource,
                    polling=polling,
                )
            )

            if polling:
                return self._deployment_wait(name, resource_group)
        except exceptions.HttpResponseError as e:
            logger.debug(e)
            raise exceptions.HttpResponseError(e.message)
        except Exception as e:
            raise e
