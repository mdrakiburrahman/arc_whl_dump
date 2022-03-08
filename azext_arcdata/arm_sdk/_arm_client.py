# ------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# ------------------------------------------------------------------------------

from ._util import dict_to_dot_notation
from jinja2 import Environment, FileSystemLoader
from knack.log import get_logger

import os
import json
import requests
import uuid

__all__ = ["ARMTemplateClient"]

logger = get_logger(__name__)


class ARMTemplateClient(object):
    API_VERSION_MAP = dict_to_dot_notation(
        {
            "CONNECTED_CLUSTER": "2021-10-01",
            "ARC_DATA_SERVICES_EXTENSION": "2021-09-01",
            "ROLE_ASSIGNMENT": "2018-09-01-preview",
            "CUSTOM_LOCATION": "2021-08-15",
            "DATA_CONTROLLER": "2021-11-01",
            "ARC_DATASERVICES_EXTENSION_RELEASE_TRAIN_TAG": "stable",
            "ARC_DATASERVICES_EXTENSION_VERSION_TAG": "1.1.18501004",
        }
    )

    def __init__(self, bearer, subscription):
        self.MGMT_URL = (
            f"https://management.azure.com/subscriptions/{subscription}"
        )
        self._subscription = subscription
        self._session = requests.Session()
        self._session.headers.update(
            {
                "Authorization": "Bearer {}".format(bearer),
                "Content-Type": "application/json",
            }
        )
        self._template = Environment(
            loader=FileSystemLoader(
                searchpath=os.path.join(os.path.dirname(__file__), "templates")
            )
        ).get_template("arm-template.tmpl")

    def create_dc(
        self,
        control,
        metrics_creds,
        resource_group,
        name,
        location,
        custom_location,
        connectivity_mode,
        cluster,
        namespace,
        storage_class=None,
        infrastructure=None,
        auto_upload_metrics=None,
        auto_upload_logs=None,
    ):
        if not namespace:
            namespace = custom_location

        # -- high order --
        spec = control.spec
        spec.settings.controller.displayName = name
        spec.credentials.controllerAdmin = "controller-login-secret"

        # -- docker --
        docker = spec.docker
        docker.registry = os.getenv("CONTROLLER_REGISTRY") or docker.registry
        docker.registry = os.getenv("DOCKER_REGISTRY") or docker.registry
        docker.repository = (
            os.getenv("CONTROLLER_REPOSITORY") or docker.repository
        )
        docker.repository = os.getenv("DOCKER_REPOSITORY") or docker.repository
        docker.imageTag = os.getenv("CONTROLLER_IMAGE_TAG") or docker.imageTag
        docker.imageTag = os.getenv("DOCKER_IMAGE_TAG") or docker.imageTag
        docker_username = os.getenv("DOCKER_USERNAME", "")
        docker_password = os.getenv("DOCKER_PASSWORD", "")
        docker_username = docker_username or os.getenv("REGISTRY_USERNAME", "")
        docker_password = docker_password or os.getenv("REGISTRY_PASSWORD", "")

        # -- azure --
        azure = spec.settings.azure
        azure.connectionMode = connectivity_mode
        azure.location = location
        azure.resourceGroup = resource_group
        azure.subscription = self._subscription

        if auto_upload_metrics is not None:
            azure.autoUploadMetrics = auto_upload_metrics
        if auto_upload_logs is not None:
            azure.autoUploadLogs = auto_upload_logs

        # -- infrastructure --
        spec.infrastructure = infrastructure or spec.infrastructure
        spec.infrastructure = spec.infrastructure or "onpremises"

        # -- storage --
        storage = spec.storage
        storage.data.className = storage_class or storage.data.className
        storage.logs.className = storage_class or storage.logs.className

        # -- resources --
        # Extension Name
        resource_name = custom_location + "-ext"
        # Role1 Name
        resource_name_1 = uuid.uuid4()
        # Role2 Name
        resource_name_2 = uuid.uuid4()

        # -- start verification --
        include_extension = True
        include_roles = True
        include_custom_location = True

        # --render --
        arm_payload = json.loads(
            self._template.render(
                control=control.to_dict,
                credentials=metrics_creds,
                docker_username=docker_username,
                docker_password=docker_password,
                cluster=cluster,
                namespace=namespace,
                custom_location=custom_location,
                include_extension=include_extension,
                include_roles=include_roles,
                include_custom_location=include_custom_location,
                resource_name=resource_name,
                resource_name_1=resource_name_1,
                resource_name_2=resource_name_2,
                ARC_DATA_SERVICES_EXTENSION_API_VERION=self.API_VERSION_MAP.ARC_DATA_SERVICES_EXTENSION,
                ROLE_ASSIGNMENT_API_VERSION=self.API_VERSION_MAP.ROLE_ASSIGNMENT,
                CUSTOM_LOCATION_API_VERSION=self.API_VERSION_MAP.CUSTOM_LOCATION,
                DATA_CONTROLLER_API_VERSION=self.API_VERSION_MAP.DATA_CONTROLLER,
                RELEASE_TRAIN_TAG=self.API_VERSION_MAP.ARC_DATASERVICES_EXTENSION_RELEASE_TRAIN_TAG,
                ARC_DATASERVICES_EXTENSION_VERSION_TAG=self.API_VERSION_MAP.ARC_DATASERVICES_EXTENSION_VERSION_TAG,
            )
        )

        logger.debug(json.dumps(arm_payload, indent=4))

        # -- make dc create request --
        url = (
            "{url}/resourceGroups/{resource_group}/providers/"
            "Microsoft.Resources/deployments/{name}?"
            "api-version={version}".format(
                url=self.MGMT_URL,
                resource_group=resource_group,
                name=name,
                version="2020-06-01",
            )
        )

        response = self._session.put(url=url, json=arm_payload)
        print(dir(response))
        print(response.text)

        return response.json

    def get_custom_location(self, resource_group, name):
        url = (
            "{url}/resourceGroups/{resource_group}/providers/"
            "Microsoft.ExtendedLocation/customLocations/"
            "{name}?api-version={version}".format(
                url=self.MGMT_URL,
                resource_group=resource_group,
                name=name,
                version=self.API_VERSION_MAP.CUSTOM_LOCATION,
            )
        )

        logger.debug(url)
        response = self._session.get(url=url)
        return False if response.status_code == "404" else response.json()

    def get_role_assign(self, resource_group, principal_id):
        url = (
            "{url}/resourceGroups/{resource_group}/providers/"
            "Microsoft.Authorization/roleAssignments?"
            "api-version={version}&%24filter=assignedTo(%27{id}c%27)".format(
                url=self.MGMT_URL,
                resource_group=resource_group,
                version=self.API_VERSION_MAP.ROLE_ASSIGNMENT,
                id=principal_id,
            )
        )

        logger.debug(url)
        response = self._session.get(url=url)
        return False if response.status_code == "404" else response.json()

    def get_extension(self, resource_group, name):
        url = (
            "{url}/resourceGroups/{resource_group}/providers/"
            "Microsoft.Kubernetes/connectedClusters/{name}/providers/"
            "Microsoft.KubernetesConfiguration/extensions?"
            "api-version={version}".format(
                url=self.MGMT_URL,
                resource_group=resource_group,
                name=name,
                version=self.API_VERSION_MAP.ARC_DATA_SERVICES_EXTENSION,
            )
        )

        logger.debug(url)
        response = self._session.get(url=url)
        return False if response.status_code == "404" else response.json()

    def get_connected_clusters(self, resource_group):
        url = (
            "{url}/resourceGroups/{resource_group}/providers/"
            "Microsoft.Kubernetes/connectedClusters?"
            "api-version={version}".format(
                url=self.MGMT_URL,
                resource_group=resource_group,
                version=self.API_VERSION_MAP.CONNECTED_CLUSTER,
            )
        )

        logger.debug(url)
        response = self._session.get(url=url)
        return False if response.status_code == "404" else response.json()
