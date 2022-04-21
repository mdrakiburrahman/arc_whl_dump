# ------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# ------------------------------------------------------------------------------

from ._util import dict_to_dot_notation, wait
from ._arm_template import ARMTemplate
from ._arm_client import arm_clients
from .swagger_1_0_0 import AzureArcDataManagementClient
from .swagger_1_0_0.models import (
    SqlManagedInstance,
    ExtendedLocation,
    SqlManagedInstanceProperties,
    SqlManagedInstanceSku,
    BasicLoginInformation,
    SqlManagedInstanceK8SRaw,
    SqlManagedInstanceK8SSpec,
    K8SScheduling,
    K8SSchedulingOptions,
    K8SResourceRequirements,
)

from azext_arcdata.core.env import Env
from azext_arcdata.core.prompt import prompt_assert
from knack.log import get_logger

import azure.core.exceptions as exceptions
import os
import json
import requests
import pydash as _
import time

__all__ = ["ArmClient"]

logger = get_logger(__name__)


class ArmClient(object):
    def __init__(self, azure_credential, subscription):
        self._arm_clients = arm_clients(subscription, azure_credential)
        self._azure_credential = azure_credential
        self._bearer = azure_credential.get_token().token
        self._subscription_id = subscription
        self._mgmt_client = AzureArcDataManagementClient(
            subscription_id=self._subscription_id,
            credential=self._azure_credential,
        )

    # ======================================================================== #
    # == DC ================================================================== #
    # ======================================================================== #

    def create_dc(
        self,
        resource_group,
        name,
        custom_location,
        connectivity_mode,
        cluster_name,
        namespace,
        path,
        storage_class=None,
        infrastructure=None,
        auto_upload_metrics=None,
        auto_upload_logs=None,
        polling=True,
    ):
        try:
            # -- check existing dc to avoid dc recreate --
            for dc in self.list_dc(resource_group):
                if dc.name == name:
                    raise Exception(
                        f"A Data Controller {name} has already been created."
                    )

            dc_client = self._arm_clients.dc

            config_file = os.path.join(path, "control.json")
            logger.debug("Configuration profile: %s", config_file)

            with open(config_file, encoding="utf-8") as input_file:
                control = dict_to_dot_notation(json.load(input_file))

            # -- high order control.json, merge in input to control.json --
            spec = control.spec
            spec.settings.controller.displayName = name
            spec.credentials.controllerAdmin = "controller-login-secret"

            # -- docker --
            docker = spec.docker
            docker.registry = Env.get("DOCKER_REGISTRY") or docker.registry
            docker.repository = (
                Env.get("DOCKER_REPOSITORY") or docker.repository
            )
            docker.imageTag = Env.get("DOCKER_IMAGE_TAG") or docker.imageTag

            # -- azure --
            azure = spec.settings.azure
            azure.connectionMode = connectivity_mode
            azure.location = dc_client.get_connected_cluster_location(
                cluster_name, resource_group
            )
            azure.resourceGroup = resource_group
            azure.subscription = self._subscription_id

            # -- log analytics --
            log_analytics = {"workspace_id": "", "primary_key": ""}
            if auto_upload_metrics is not None:
                azure.autoUploadMetrics = auto_upload_metrics
            if auto_upload_logs is not None:
                azure.autoUploadLogs = auto_upload_logs
                w_id = Env.get("WORKSPACE_ID")
                w_key = Env.get("WORKSPACE_SHARED_KEY")
                if not w_id:
                    w_id = prompt_assert("Log Analytics workspace ID: ")
                if not w_key:
                    w_key = prompt_assert("Log Analytics primary key: ")

                log_analytics["workspace_id"] = w_id
                log_analytics["primary_key"] = w_key

            # -- infrastructure --
            spec.infrastructure = infrastructure or spec.infrastructure
            spec.infrastructure = spec.infrastructure or "onpremises"

            # -- storage --
            storage = spec.storage
            storage.data.className = storage_class or storage.data.className
            storage.logs.className = storage_class or storage.logs.className

            if not storage.data.className or not storage.logs.className:
                storage_class = prompt_assert("Storage class: ")
                storage.data.className = storage_class
                storage.logs.className = storage_class

            properties = {
                "metrics_credentials": Env.get_log_and_metrics_credentials(),
                "custom_location": custom_location,
                "cluster_name": cluster_name,
                "resource_group": resource_group,
                "log_analytics": log_analytics,
                "namespace": dc_client.resolve_namespace(
                    namespace,
                    custom_location,
                    cluster_name,
                    resource_group,
                ),
            }

            # -- attempt to create cluster --
            print("")
            print("Deploying data controller")
            print("")
            print(
                "NOTE: Data controller creation can take a significant "
                "amount of time depending \non configuration, network "
                "speed, and the number of nodes in the cluster."
            )
            print("")

            # -- make dc create request via ARM --
            tmpl = ARMTemplate(
                dc_client, self._arm_clients.hydration
            ).render_dc(control.to_dict, properties)

            return dc_client.create(name, resource_group, tmpl, polling=polling)
        except exceptions.HttpResponseError as e:
            logger.debug(e)
            raise exceptions.HttpResponseError(e.message)
        except Exception as e:
            raise e

    def __create_depreciated_dc__(
        self,
        resource_group,
        name,
        location,
        custom_location,
        connectivity_mode,
        path,
        storage_class=None,
        infrastructure=None,
        auto_upload_metrics=None,
        auto_upload_logs=None,
        polling=True,
    ):

        """
        This is the original dc create that expected the following to already
        be created:
        - extensions
        - custom-location,
        - roll assignments.

        This will eventually be removed.
        """
        try:
            return self._arm_clients.dc.__create_depreciated_dc__(
                resource_group,
                name,
                location,
                custom_location,
                connectivity_mode,
                path,
                storage_class=storage_class,
                infrastructure=infrastructure,
                auto_upload_metrics=auto_upload_metrics,
                auto_upload_logs=auto_upload_logs,
                polling=polling,
            )
        except exceptions.HttpResponseError as e:
            logger.debug(e)
            raise exceptions.HttpResponseError(e.message)
        except Exception as e:
            raise e

    def get_dc(self, resource_group, name):
        return self._arm_clients.dc.get(name, resource_group)

    def list_dc(self, resource_group):
        return self._arm_clients.dc.list(resource_group)

    def update_dc(self, resource_group, name, properties: dict):
        return self._arm_clients.dc.patch(
            name, resource_group, properties=properties
        )

    def delete_dc(self, resource_group, name, polling=True):
        return self._arm_clients.dc.delete(
            name, resource_group, polling=polling
        )

    def upgrade_dc(
        self,
        resource_group,
        name,
        target,
        dry_run=False,
        polling=True,
    ):
        return self._arm_clients.dc.upgrade(
            name,
            resource_group,
            target,
            dry_run=dry_run,
            polling=polling,
        )

    # ======================================================================== #
    # == SQL MI ============================================================== #
    # ======================================================================== #

    def get_mi_resource_url(self, resource_group, resource_name):
        return (
            "https://management.azure.com/subscriptions/{}/resourceGroups"
            "/{}/providers/Microsoft.AzureArcData/sqlManagedInstances/{}"
            "?api-version={}".format(
                self._subscription_id,
                resource_group,
                resource_name,
                "2021-11-01",
            )
        )

    def create_sqlmi(
        self,
        name,
        location,
        custom_location,
        resource_group,
        path=None,
        replicas=None,
        readable_secondaries=None,
        cores_limit=None,
        cores_request=None,
        memory_limit=None,
        memory_request=None,
        storage_class_data=None,
        storage_class_logs=None,
        storage_class_datalogs=None,
        storage_class_backups=None,
        volume_size_data=None,
        volume_size_logs=None,
        volume_size_datalogs=None,
        volume_size_backups=None,
        license_type=None,
        tier=None,
        dev=None,
        polling=True,
        # -- Not Support for now --
        # noexternal_endpoint=None,
        # certificate_public_key_file=None,
        # certificate_private_key_file=None,
        # service_certificate_secret=None,
        # admin_login_secret=None,
        # collation=None,
        # language=None,
        # agent_enabled=None,
        # trace_flags=None,
        # time_zone=None,
        # retention_days=None,
        # labels=None,
        # annotations=None,
        # service_labels=None,
        # service_annotations=None,
        # storage_labels=None,
        # storage_annotations=None,
    ):
        try:
            # -- check existing sqlmi's to avoid duplicate sqlmi create --
            sqlmi_names = []
            for mi in self.list_sqlmi(resource_group):
                sqlmi_names.append(mi.as_dict()["name"])
            if name in sqlmi_names:
                raise ValueError(
                    "A Managed SQL Instance {name} has already been "
                    "created.".format(name=name)
                )

            # -- acquire sqlmi username/password --
            cred = Env.get_sqlmi_credentials()

            # -- properties --
            #
            BASE = os.path.dirname(os.path.realpath(__file__))
            TEMPLATE_DIR = os.path.join(BASE, "templates")
            SQLMI_SPEC_MERGE = os.path.join(
                TEMPLATE_DIR, "sqlmi-create-properties.json"
            )
            with open(path or SQLMI_SPEC_MERGE, encoding="utf-8") as input_file:
                all_prop = json.load(input_file)
                logger.debug(json.dumps(all_prop, indent=4))
            k8s = all_prop["properties"]["k8sRaw"]

            # -- storage --
            if storage_class_data:
                k8s["spec"]["storage"]["data"]["volumes"][0][
                    "className"
                ] = storage_class_data
            if storage_class_logs:
                k8s["spec"]["storage"]["logs"]["volumes"][0][
                    "className"
                ] = storage_class_logs
            if storage_class_datalogs:
                k8s["spec"]["storage"]["datalogs"]["volumes"][0][
                    "className"
                ] = storage_class_datalogs
            if storage_class_backups:
                k8s["spec"]["storage"]["backups"]["volumes"][0][
                    "className"
                ] = storage_class_backups
            if volume_size_data:
                k8s["spec"]["storage"]["data"]["volumes"][0][
                    "size"
                ] = volume_size_data
            if volume_size_logs:
                k8s["spec"]["storage"]["logs"]["volumes"][0][
                    "size"
                ] = volume_size_logs
            if volume_size_datalogs:
                k8s["spec"]["storage"]["datalogs"]["volumes"][0][
                    "size"
                ] = volume_size_datalogs
            if volume_size_backups:
                k8s["spec"]["storage"]["backups"]["volumes"][0][
                    "size"
                ] = volume_size_backups

            # ==== Billing ====================================================

            # -- dev --
            if dev:
                k8s["spec"]["dev"] = True

            # -- scheduling --
            if cores_limit:
                k8s["spec"]["scheduling"]["default"]["resources"]["limits"][
                    "cpu"
                ] = cores_limit
            if cores_request:
                k8s["spec"]["scheduling"]["default"]["resources"]["requests"][
                    "cpu"
                ] = cores_request
            if memory_limit:
                k8s["spec"]["scheduling"]["default"]["resources"]["limits"][
                    "memory"
                ] = memory_limit
            if memory_request:
                k8s["spec"]["scheduling"]["default"]["resources"]["requests"][
                    "memory"
                ] = memory_request

            # -- replicas --
            if replicas:
                k8s["spec"]["replicas"] = replicas

            # -- readable secondaries --
            if readable_secondaries:
                k8s["spec"]["readableSecondaries"] = int(readable_secondaries)

            # -- license type --
            if license_type:
                all_prop["properties"]["licenseType"] = license_type

            # -- tier --
            if tier:
                all_prop["sku"]["tier"] = tier

            all_dcs = self.list_dc(resource_group)
            dc_name_list = []
            dc_in_rg = {}
            for curr_dc in all_dcs:
                dc_name_list.append(curr_dc.as_dict()["name"])
            if not dc_name_list:
                raise Exception(
                    "No data controller was found in the resource group."
                )
            else:
                dc_in_rg = self.get_dc(resource_group, dc_name_list[0])
                service_type = dc_in_rg.properties.k8_s_raw["spec"]["services"][
                    0
                ]["serviceType"]
                k8s["spec"]["services"]["primary"]["type"] = service_type

            # Force the namespace to be aligned with dc
            #
            if (
                dc_in_rg
                and dc_in_rg.properties
                and dc_in_rg.properties.k8_s_raw
                and "metadata" in dc_in_rg.properties.k8_s_raw
                and "namespace" in dc_in_rg.properties.k8_s_raw["metadata"]
            ):
                k8s["spec"]["metadata"][
                    "namespace"
                ] = dc_in_rg.properties.k8_s_raw["metadata"]["namespace"]

            # -- TODO: Remove Validation check --
            #
            self._is_valid_sqlmi_create(
                cores_limit=k8s["spec"]["scheduling"]["default"]["resources"][
                    "limits"
                ]["cpu"],
                cores_request=k8s["spec"]["scheduling"]["default"]["resources"][
                    "requests"
                ]["cpu"],
                memory_limit=k8s["spec"]["scheduling"]["default"]["resources"][
                    "limits"
                ]["memory"],
                memory_request=k8s["spec"]["scheduling"]["default"][
                    "resources"
                ]["requests"]["memory"],
                volume_size_data=k8s["spec"]["storage"]["data"]["volumes"][0][
                    "size"
                ],
                volume_size_logs=k8s["spec"]["storage"]["logs"]["volumes"][0][
                    "size"
                ],
                volume_size_datalogs=k8s["spec"]["storage"]["datalogs"][
                    "volumes"
                ][0]["size"],
                volume_size_backups=k8s["spec"]["storage"]["backups"][
                    "volumes"
                ][0]["size"],
                license_type=all_prop["properties"]["licenseType"],
                tier=all_prop["sku"]["tier"],
            )

            # TODO: Remove Compose additional properties. Values have been
            #  verified in the set
            #
            safe_set = {
                "dev",
                "storage",
                "license_type",
                "services",
                "backup",
                "settings",
                "metadata",
                "dev",
                "readableSecondaries",
            }
            additional_properties = {}
            for key in k8s["spec"]:
                if key in safe_set:
                    additional_properties[key] = k8s["spec"][key]

            resources = k8s["spec"]["scheduling"]["default"]["resources"]

            # -- Build properties --
            properties = SqlManagedInstanceProperties(
                data_controller_id=dc_in_rg.name,
                admin="controlleradmin",
                basic_login_information=BasicLoginInformation(
                    username=cred.username,
                    password=cred.password,
                ),
                license_type=all_prop["properties"]["licenseType"],
                k8_s_raw=SqlManagedInstanceK8SRaw(
                    spec=SqlManagedInstanceK8SSpec(
                        additional_properties=additional_properties,
                        replicas=k8s["spec"]["replicas"],
                        scheduling=K8SScheduling(
                            default=K8SSchedulingOptions(
                                resources=K8SResourceRequirements(
                                    limits={
                                        "cpu": resources["limits"]["cpu"],
                                        "memory": resources["limits"]["memory"],
                                    },
                                    requests={
                                        "cpu": resources["requests"]["cpu"],
                                        "memory": resources["requests"][
                                            "memory"
                                        ],
                                    },
                                )
                            )
                        ),
                    )
                ),
            )

            # -- Build final mi request model --
            sql_managed_instance = SqlManagedInstance(
                location=location,
                properties=properties,
                extended_location=ExtendedLocation(
                    name=(
                        "/subscriptions/"
                        + self._subscription_id
                        + "/resourcegroups/"
                        + resource_group
                        + "/providers/microsoft.extendedlocation/"
                        "customlocations/" + custom_location
                    ),
                    type="CustomLocation",
                ),
                sku=SqlManagedInstanceSku(
                    tier=all_prop["sku"]["tier"], dev=None
                ),
                tags=all_prop["tags"],
            )

            self._mgmt_client.sql_managed_instances.begin_create(
                resource_group_name=resource_group,
                sql_managed_instance_name=name,
                sql_managed_instance=sql_managed_instance,
            )

            if polling:
                # Setting a total wait time of 600 sec with a step of 5 sec
                wait(
                    self.sqlmi_deployment_completed,
                    resource_group,
                    name,
                )
                if (
                    self.sqlmi_deployment_completed(resource_group, name)
                    != "Ready"
                ):
                    raise Exception(
                        "SQLMI deployment failed. Please check your sqlmi status "
                        "in portal or reset this create process."
                    )
                return self.get_sqlmi(resource_group, name)
        except exceptions.HttpResponseError as e:
            logger.debug(e)
            raise exceptions.HttpResponseError(e.message)
        except Exception as e:
            raise e

    def sqlmi_deployment_completed(self, resource_group, name):
        get_result = self.get_sqlmi(resource_group, name)
        if (
            get_result
            and get_result["properties"]
            and get_result["properties"]["k8_s_raw"]
            and "status" in get_result["properties"]["k8_s_raw"]
            and "state" in get_result["properties"]["k8_s_raw"]["status"]
        ):
            return get_result["properties"]["k8_s_raw"]["status"]["state"]
        else:
            # Status is unknow, so we set it to "Wait" for now.
            return "Wait"

    def delete_sqlmi(self, rg_name, sqlmi_name, polling=True):
        try:
            result = self._mgmt_client.sql_managed_instances.begin_delete(
                resource_group_name=rg_name,
                sql_managed_instance_name=sqlmi_name,
                polling=polling,
            )

            return result
        except exceptions.HttpResponseError as e:
            logger.debug(e)
            raise exceptions.HttpResponseError(e.message)
        except Exception as e:
            raise e

    def get_sqlmi(self, rg_name, sqlmi_name):
        try:
            result = self._mgmt_client.sql_managed_instances.get(
                resource_group_name=rg_name,
                sql_managed_instance_name=sqlmi_name,
            ).as_dict()

            logger.debug(json.dumps(result, indent=4))

            return result
        except exceptions.HttpResponseError as e:
            logger.debug(e)
            raise exceptions.HttpResponseError(e.message)
        except Exception as e:
            raise e

    def get_sqlmi_as_obj(self, rg_name, sqlmi_name):
        try:
            result = self._mgmt_client.sql_managed_instances.get(
                resource_group_name=rg_name,
                sql_managed_instance_name=sqlmi_name,
            )

            logger.debug(json.dumps(result.as_dict(), indent=4))

            return result
        except exceptions.HttpResponseError as e:
            logger.debug(e)
            raise exceptions.HttpResponseError(e.message)
        except Exception as e:
            raise e

    def get_arc_datacontroller(self, resource_group):
        """
        TODO: It is possible to have more than one data controller in a resource group.
        This should be updated to query Azure once workitem #1316334 has been completed
        """
        all_dcs = self.list_dc(resource_group)
        for curr_dc in all_dcs:
            dc = curr_dc.as_dict()
            dc_spec = dc["properties"]["k8_s_raw"]
            if "status" in dc_spec and "state" in dc_spec["status"]:
                if dc_spec["status"]["state"].lower() != "duplicateerror":
                    return dc_spec

    def upgrade_sqlmi(
        self,
        resource_group,
        name,
        desired_version,
        no_wait=True,
    ):
        try:
            if desired_version is None:
                dc = self.get_arc_datacontroller(resource_group)
                desired_version = dc["spec"]["docker"]["imageTag"]

            url = self.get_mi_resource_url(resource_group, name)

            headers = {
                "Authorization": "Bearer {}".format(self._bearer),
                "Content-Type": "application/json",
            }

            response = requests.get(url=url, headers=headers)

            if response.status_code == 404:
                logger.debug(response.text)
                raise Exception(
                    "Error while retrieving SQL MI instance with name '{}' in resource group '{}'".format(
                        name, resource_group
                    )
                )

            sqlmi = response.json()

            # We cannot initiate a new PUT request if a previous request is still
            # in the Accepted state.
            #
            if sqlmi["properties"]["provisioningState"] == "Accepted":
                raise Exception(
                    "An existing operation is in progress. Please check your SQL MI's status in the Azure Portal."
                )

            if "update" not in sqlmi["properties"]["k8sRaw"]["spec"]:
                sqlmi["properties"]["k8sRaw"]["spec"]["update"] = {}

            sqlmi["properties"]["k8sRaw"]["spec"]["update"][
                "desiredVersion"
            ] = desired_version

            template = {}
            template["location"] = sqlmi["location"]
            template["extendedLocation"] = sqlmi["extendedLocation"]
            template["properties"] = sqlmi["properties"]
            template["sku"] = sqlmi["sku"]

            payload = json.dumps(template)

            # The mgmt library will currently strip away most of the spec when it converts the json payload to a ManagementInstance object.
            # This not only removes the update section, but most of the rest of the spec as well. For now we will need to manually submit the ARM request.
            #
            response = requests.put(url=url, headers=headers, data=payload)
            if response.status_code != 201:
                logger.debug(response.text)
                raise Exception("Error while upgrading SQL MI instance.")

            # Wait for the operation to be accepted
            #
            for _ in range(0, 60, 5):
                mi = self.get_sqlmi(resource_group, name)
                if mi["properties"]["provisioning_state"] != "Accepted":
                    break
                else:
                    time.sleep(5)

            if mi["properties"]["provisioning_state"] == "Failed":
                raise Exception(
                    "The ARM request to upgrade the SQL MI instance failed. Please check your SQL MI's status in the Azure Portal for more information."
                )

            if not no_wait:
                # Setting a total wait time of 600 sec with a step of 5 sec
                for _ in range(0, 600, 5):
                    if self.sqlmi_upgrade_completed(resource_group, name):
                        break
                    else:
                        time.sleep(5)

                if not self.sqlmi_upgrade_completed(resource_group, name):
                    raise Exception(
                        "SQLMI upgrade failed. Please check your SQL MI's status in the Azure Portal for more information."
                    )

        except exceptions.HttpResponseError as e:
            logger.debug(e)
            raise exceptions.HttpResponseError(e.message)
        except Exception as e:
            raise e

    def sqlmi_upgrade_completed(self, resource_group, name):
        url = self.get_mi_resource_url(resource_group, name)

        headers = {
            "Authorization": "Bearer {}".format(self._bearer),
            "Content-Type": "application/json",
        }

        get_result = requests.get(url=url, headers=headers).json()

        return (
            _.get(get_result, "properties.k8sRaw.status.state", False)
            == "Ready"
        )

    def update_sqlmi(
        self,
        name,
        replicas=None,
        readable_secondaries=None,
        cores_limit=None,
        cores_request=None,
        memory_limit=None,
        memory_request=None,
        license_type=None,
        no_wait=False,
        labels=None,
        annotations=None,
        service_labels=None,
        service_annotations=None,
        agent_enabled=None,
        trace_flags=None,
        retention_days=None,
        resource_group=None,
    ):
        try:
            # get_sqmlmi then mixin properties
            response = self.get_sqlmi_as_obj(resource_group, name)
            resources = (
                response.properties.k8_s_raw.spec.scheduling.default.resources
            )
            additional_properties = (
                response.properties.k8_s_raw.spec.additional_properties
            )
            if (
                response.properties.provisioning_state == "Accepted"
                or response.properties.provisioning_state == "Deleting"
            ):
                raise Exception(
                    "An existing operation is in progress. Please check your "
                    "sqlmi's status in the Azure Portal."
                )
            if cores_limit and cores_limit != resources.limits["cpu"]:
                resources.limits["cpu"] = cores_limit
            if cores_request and cores_request != resources.requests["cpu"]:
                resources.requests["cpu"] = cores_request
            if memory_limit and memory_limit != resources.limits["memory"]:
                resources.limits["memory"] = memory_limit
            if (
                memory_request
                and memory_request != resources.requests["memory"]
            ):
                resources.requests["memory"] = memory_request
            if (
                agent_enabled
                and agent_enabled
                != additional_properties["settings"]["sqlagent"]["enabled"]
            ):
                additional_properties["settings"]["sqlagent"][
                    "enabled"
                ] = agent_enabled
            if (
                retention_days
                and retention_days
                != additional_properties["backup"]["retentionPeriodInDays"]
            ):
                additional_properties["backup"][
                    "retentionPeriodInDays"
                ] = retention_days
            if trace_flags:
                additional_properties["settings"]["traceFlags"] = trace_flags
            if labels:
                additional_properties["metadata"]["labels"] = labels
            if annotations:
                additional_properties["metadata"]["annotations"] = annotations
            if service_labels:
                additional_properties["services"]["primary"][
                    "labels"
                ] = service_labels
            if service_annotations:
                additional_properties["services"]["primary"][
                    "annotations"
                ] = service_annotations
            if replicas is None:
                replicas = response.properties.k8_s_raw.spec.replicas
            if readable_secondaries:
                response.properties.readableSecondaries = readable_secondaries
            if license_type:
                response.properties.license_type = license_type

            # -- Validation check -- prisioning is very slow so we check here
            #
            self._is_valid_sqlmi_create(
                cores_limit=resources.limits["cpu"],
                cores_request=resources.requests["cpu"],
                memory_limit=resources.limits["memory"],
                memory_request=resources.requests["memory"],
                volume_size_data=additional_properties["storage"]["data"][
                    "volumes"
                ][0]["size"],
                volume_size_logs=additional_properties["storage"]["logs"][
                    "volumes"
                ][0]["size"],
                volume_size_datalogs=additional_properties["storage"][
                    "datalogs"
                ]["volumes"][0]["size"],
                volume_size_backups=additional_properties["storage"]["backups"][
                    "volumes"
                ][0]["size"],
                license_type=response.properties.license_type,
                tier=response.sku.tier,
            )

            self._mgmt_client.sql_managed_instances.begin_create(
                resource_group_name=resource_group,
                sql_managed_instance_name=name,
                sql_managed_instance=response,
            )

            if not no_wait:
                wait(
                    self.sqlmi_deployment_completed,
                    resource_group,
                    name,
                )
                if (
                    self.sqlmi_deployment_completed(resource_group, name)
                    != "Ready"
                ):
                    raise Exception(
                        "SQLMI deployment failed. Please check your sqlmi status "
                        "in portal or reset this create process."
                    )
                return self.get_sqlmi(resource_group, name)
        except exceptions.HttpResponseError as e:
            logger.debug(e)
            raise exceptions.HttpResponseError(e.message)
        except Exception as e:
            raise e

    def list_sqlmi(self, rg_name):
        try:
            result = (
                self._mgmt_client.sql_managed_instances.list_by_resource_group(
                    rg_name
                )
            )

            return result
        except exceptions.HttpResponseError as e:
            logger.debug(e)
            raise exceptions.HttpResponseError(e.message)
        except Exception as e:
            raise e

    def _is_valid_sqlmi_create(
        self,
        cores_limit,
        cores_request,
        memory_limit,
        memory_request,
        volume_size_data,
        volume_size_logs,
        volume_size_datalogs,
        volume_size_backups,
        license_type,
        tier,
    ):
        tier_set = {"gp", "GeneralPurpose", "bc", "BusinessCritical"}
        license_type_set = {"BasePrice", "LicenseIncluded", "DisasterRecovery"}
        try:
            if tier not in tier_set:
                raise Exception("Tier {0} is not a support input.".format(tier))

            if license_type not in license_type_set:
                raise Exception(
                    "License type {0} is not a support input.".format(
                        license_type
                    )
                )

            # Check the input end with Gi
            #
            Gi_val_list = [
                memory_limit,
                memory_request,
                volume_size_data,
                volume_size_logs,
                volume_size_datalogs,
                volume_size_backups,
            ]

            Gi_name_list = [
                "Memory limit",
                "Memory request",
                "Volume size data",
                "Volume size logs",
                "Volume size datalogs",
                "Volume size backups",
            ]

            for i in range(len(Gi_val_list)):
                if "Gi" not in str(Gi_val_list[i]):
                    raise ValueError(
                        "{0} {1} is invalid. Unit Gi must be part of this input.".format(
                            Gi_name_list[i], Gi_val_list[i]
                        )
                    )

                # Check the number in the input
                #
                if not (str(Gi_val_list[i]).replace("Gi", "")).isdigit():
                    raise ValueError(
                        "{0} {1} is invalid. A number must be part of this input.".format(
                            Gi_name_list[i], Gi_val_list[i]
                        )
                    )
                else:
                    Gi_val_list[i] = int(str(Gi_val_list[i]).replace("Gi", ""))

            # Check the input which should be digits.
            #
            digit_val_list = [cores_limit, cores_request]
            digit_name_list = ["Cores limit", "Cores request"]
            for i in range(len(digit_val_list)):
                if not str(digit_val_list[i]).isdigit():
                    raise ValueError(
                        "{0} {1} is invalid. Only a number can be part of this input.".format(
                            digit_name_list[i], digit_val_list[i]
                        )
                    )
                else:
                    digit_val_list[i] = int(str(digit_val_list[i]))

            # Check the resource scheduling config
            #
            if Gi_val_list[0] < Gi_val_list[1]:
                raise ValueError(
                    "Memory request cannot be larger than memory limit."
                )
            if digit_val_list[0] < digit_val_list[1]:
                raise ValueError(
                    "Cores request cannot be larger than cores limit."
                )

            # Check the scheduling per tier
            #
            gp_tiers = {"gp", "GeneralPurpose"}
            if tier in gp_tiers:
                if Gi_val_list[0] > 128 or Gi_val_list[0] < 2:
                    raise ValueError(
                        "Invalid {0}. Tier {1} can only support an input in the range from 2 to 128Gi.".format(
                            Gi_name_list[0], tier
                        )
                    )
                if Gi_val_list[1] > 128 or Gi_val_list[1] < 2:
                    raise ValueError(
                        "Invalid {0}. Tier {1} can only support an input in the range from 2 to 128Gi.".format(
                            Gi_name_list[1], tier
                        )
                    )
                if digit_val_list[0] > 24 or digit_val_list[0] < 1:
                    raise ValueError(
                        "Invalid {0}. Tier {1} can only support an input in the range from 1 to 24.".format(
                            digit_name_list[0], tier
                        )
                    )
                if digit_val_list[1] > 24 or digit_val_list[1] < 1:
                    raise ValueError(
                        "Invalid {0}. Tier {1} can only support an input in the range from 1 to 24.".format(
                            digit_name_list[1], tier
                        )
                    )
            else:
                if Gi_val_list[0] < 2:
                    raise ValueError(
                        "Invalid {0}. Tier {1} can only support an input in the range >= 2Gi".format(
                            Gi_name_list[0], tier
                        )
                    )
                if Gi_val_list[1] < 2:
                    raise ValueError(
                        "Invalid {0}. Tier {1} can only support aa input in the range >= 2Gi.".format(
                            Gi_name_list[1], tier
                        )
                    )
                if digit_val_list[0] < 1:
                    raise ValueError(
                        "Invalid {0}. Tier {1} can only support an input in the range >=1.".format(
                            digit_name_list[0], tier
                        )
                    )
                if digit_val_list[1] < 1:
                    raise ValueError(
                        "Invalid {0}. Tier {1} can only support an input in the range >=1.".format(
                            digit_name_list[1], tier
                        )
                    )

        except Exception as e:
            raise e
