# ------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# ------------------------------------------------------------------------------

from ._util import dict_to_dot_notation
from jinja2 import Environment, FileSystemLoader
from knack.log import get_logger
import azure.core.exceptions as exceptions
from azext_arcdata.core.prompt import prompt_assert

import os
import json
import requests
import uuid

__all__ = ["ARMTemplate"]

logger = get_logger(__name__)


class ARMTemplate(object):
    EXT_TAG_MAP = dict_to_dot_notation(
        {
            "ARC_DATASERVICES_EXTENSION_RELEASE_TRAIN": "stable",
            "ARC_DATASERVICES_EXTENSION_VERSION": "1.1.19091004",
        }
    )

    def __init__(self, dc_client, hydration_client):
        self._dc_client = dc_client
        self._hydration_client = hydration_client
        self._template = Environment(
            loader=FileSystemLoader(
                searchpath=os.path.join(os.path.dirname(__file__), "templates")
            )
        ).get_template("arm-template.tmpl")

    def render_dc(self, control, properties):
        env_var_overrides = self._environment_variable_overrides()
        cluster_name = properties.get("cluster_name")
        custom_location = properties.get("custom_location")
        namespace = properties.get("namespace")
        resources = self._resources(
            namespace,
            custom_location,
            cluster_name,
            properties.get("resource_group"),
        )

        arm = json.loads(
            self._template.render(
                resources=resources,
                control=control,
                credentials=properties.get("metrics_credentials"),
                log_analytics=properties.get("log_analytics"),
                extensions=env_var_overrides.extensions,
                docker_username=env_var_overrides.docker_username,
                docker_password=env_var_overrides.docker_password,
                cluster=cluster_name,
                namespace=namespace,
                custom_location=custom_location,
                resource_name=custom_location + "-ext",  # extension name
                resource_name_1=uuid.uuid4(),  # role1 name
                resource_name_2=uuid.uuid4(),  # role2 name
            )
        )

        # -- log --
        d = dict_to_dot_notation(arm.copy())
        d.properties.parameters.metricsAndLogsDashboardPassword_4 = "*"
        d.properties.parameters.logAnalyticsPrimaryKey_4 = "*"
        d.properties.parameters.imagePassword = "*"
        logger.debug(json.dumps(d.to_dict, indent=4))

        return arm

    def _resources(
        self, namespace, custom_location, cluster_name, resource_group
    ):
        """
        :return: Dynamic list of ordered arm template resources.
        """
        resource_matrix = self._build_included_resource_matrix(
            namespace, custom_location, cluster_name, resource_group
        )

        # -- Build needed resources --
        resources = []  # Note: insert order matters
        depends_on = None

        if resource_matrix.include_extension:
            resources.append(
                {"dependsOn": depends_on, "tmpl": "extensions.tmpl"}
            )
            depends_on = "resourceName"

        if resource_matrix.include_roles_1:
            resources.append(
                {"dependsOn": depends_on, "tmpl": "roles-assignments-1.tmpl"}
            )
            depends_on = "resourceName_1"

        if resource_matrix.include_roles_2:
            resources.append(
                {"dependsOn": depends_on, "tmpl": "roles-assignments-2.tmpl"}
            )
            depends_on = "resourceName_2"

        if resource_matrix.include_custom_location:
            resources.append(
                {"dependsOn": depends_on, "tmpl": "custom-locations.tmpl"}
            )
            depends_on = "resourceName_3"

        if resource_matrix.include_resource_hydration:
            resources.append(
                {"dependsOn": depends_on, "tmpl": "resource-hydration.tmpl"}
            )
            depends_on = "resourceSyncRuleName"

        # -- data-controller always created --
        resources.append(
            {"dependsOn": depends_on, "tmpl": "datacontroller.tmpl"}
        )

        return resources

    def _environment_variable_overrides(self):
        # -- docker env overrides --
        docker_username = os.getenv("DOCKER_USERNAME", "")
        docker_password = os.getenv("DOCKER_PASSWORD", "")
        docker_username = docker_username or os.getenv("REGISTRY_USERNAME", "")
        docker_password = docker_password or os.getenv("REGISTRY_PASSWORD", "")

        # -- extension tag env overrides --
        extensions = self.EXT_TAG_MAP
        ext_train = os.getenv("ARC_DATASERVICES_EXTENSION_RELEASE_TRAIN")
        ext_tag = os.getenv("ARC_DATASERVICES_EXTENSION_VERSION_TAG")
        if ext_train:
            extensions.ARC_DATASERVICES_EXTENSION_RELEASE_TRAIN = ext_train
        if ext_tag:
            extensions.ARC_DATASERVICES_EXTENSION_VERSION = ext_tag

        return dict_to_dot_notation(
            {
                "docker_username": docker_username,
                "docker_password": docker_password,
                "extensions": extensions.to_dict,
            }
        )

    def _build_included_resource_matrix(
        self, namespace, custom_location, cluster_name, resource_group
    ):
        try:
            # Assume all resources exist hence do not include
            resource_matrix = dict_to_dot_notation(
                {
                    "include_extension": False,
                    "include_roles_1": False,
                    "include_roles_2": False,
                    "include_custom_location": False,
                    "include_resource_hydration": False,
                }
            )

            # -- verify extension and role info --
            extension = self._dc_client.get_extensions(
                cluster_name, resource_group
            )

            if len(extension["value"]) == 0:
                resource_matrix.include_extension = True
                resource_matrix.include_roles_1 = True
                resource_matrix.include_roles_2 = True
            else:
                # contributor role and monitoring publisher role
                roles = self._dc_client.get_role_assignments(
                    cluster_name, resource_group
                )
                if len(roles["value"]) == 0:
                    resource_matrix.include_roles_1 = True
                    resource_matrix.include_roles_2 = True

            resource_graph = self._dc_client.get_resource_graph(
                cluster_name, resource_group, namespace
            )
            count = resource_graph["count"]

            if count == 0:  # Include CL
                resource_matrix.include_custom_location = True
            elif count == 1:
                # check if provided CL match existing CL, if not error
                cl_name = resource_graph["data"][0]["customLocationName"]
                if custom_location != cl_name:
                    raise Exception(
                        f"An existing custom location name "
                        f"{cl_name} has been found in the cluster "
                        f"{cluster_name}. A cluster can only "
                        f"have one custom location."
                    )
            else:
                raise Exception(
                    f"Multiple custom location or namespace have been found "
                    f"under cluster {cluster_name}. A "
                    f"cluster can only have one custom location with one "
                    f"namespace."
                )

            # -- default to False
            if not self._hydration_client.has_hydration(
                resource_group, custom_location
            ):
                resource_matrix.include_resource_hydration = True

            logger.debug(resource_matrix)

            return resource_matrix
        except exceptions.HttpResponseError as e:
            logger.debug(e)
            raise exceptions.HttpResponseError(e.message)
        except Exception as e:
            raise e
