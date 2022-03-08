# ------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# ------------------------------------------------------------------------------
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.common.credentials import get_cli_profile
from msrestazure.azure_exceptions import CloudError
from msrestazure.tools import is_valid_resource_id, parse_resource_id
from azext_arcdata.kubernetes_sdk.HttpCodes import HTTPCodes
from azure.cli.core.azclierror import (
    AzureResponseError,
    ResourceNotFoundError,
    ValidationError,
)
from azure.core.exceptions import HttpResponseError
from azure.identity._credentials.azure_cli import AzureCliCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.extendedlocation import CustomLocations
from . import constants as azure_constants
from azext_arcdata.dc.azure.ad_auth_util import acquire_token
from azext_arcdata.dc.azure.constants import (
    EXTENSION_API_VERSION,
    INSTANCE_TYPE_POSTGRES,
    INSTANCE_TYPE_SQL,
)
from azext_arcdata.dc.export_util import (
    format_sqlmi_license_type_for_azure,
    format_sqlmi_tier_for_azure,
)
from azext_arcdata.sqlmi.constants import SQL_MI_SKU_NAME_VCORE
from azext_arcdata.kubernetes_sdk.client import http_status_codes
from azext_arcdata.dc.exceptions import (
    ServerError,
    RequestTimeoutError,
)
from azext_arcdata.core.output import OutputStream
from azext_arcdata.core.util import retry
from urllib3.exceptions import NewConnectionError, MaxRetryError, TimeoutError
from knack.log import get_logger
from requests.exceptions import HTTPError

import json
import os
import uuid
import pydash as _
import requests

CONNECTION_RETRY_ATTEMPTS = 12
RETRY_INTERVAL = 5

log = get_logger(__name__)
err_msg = '\tFailed to {} resource: "{}" with error: "{}"'

__all__ = ["AzureResourceClient"]


class AzureResourceClient(object):
    """
    Azure Resource Client
    """

    @property
    def stderr(self):
        return OutputStream().stderr.write

    def create_azure_resource(
        self,
        instance_type,
        data_controller_name,
        resource_name,
        subscription_id,
        resource_group_name,
        location,
        extended_properties=None,
    ):
        """
        Create Azure resource by instance
        :param location: Azure location
        :param resource_group_name: resource group name
        :param subscription_id: Azure subscription ID
        :param resource_name: resource name
        :param data_controller_name: data controller name
        :param instance_type: Azure resource type
        :param extended_properties: Dict or object containing addional
        properties to be included in the properties bag.
        :return:
        """

        data_controller_id = azure_constants.RESOURCE_URI.format(
            subscription_id, resource_group_name, "dataControllers", data_controller_name
        )

        params = {
            "location": location,
            "properties": {"dataControllerId": data_controller_id},
        }

        if extended_properties:
            params["properties"].update(extended_properties)
            if instance_type == INSTANCE_TYPE_SQL:
                self.populate_sql_properties(params, extended_properties)

        url, resource_uri = self._get_request_url(
            subscription_id, resource_group_name, instance_type, resource_name
        )
        try:
            response = requests.put(
                url,
                headers=self._get_header(resource_uri),
                data=json.dumps(params),
            )
            response.raise_for_status()
            print(
                '\t"{}" has been uploaded to Azure "{}".'.format(
                    resource_name, resource_uri
                )
            )
            log.info(
                "Create Azure resource {} response header: {}".format(
                    resource_uri, response.headers
                )
            )
        except requests.exceptions.HTTPError as e:
            response_json_string = json.loads(response.text)
            if (
                "error" in response_json_string
                and "message" in response_json_string["error"]
            ):
                self.stderr(response_json_string["error"]["message"])
            log.error(err_msg.format("Create", resource_name, e.response.text))

    def _get_azure_resource(
        self, resource_name, instance_type, subscription_id, resource_group_name
    ):
        url, resource_uri = self._get_request_url(
            subscription_id, resource_group_name, instance_type, resource_name
        )
        try:
            response = requests.get(url, headers=self._get_header(resource_uri))
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            log.error(err_msg.format("Get", resource_name, e.response.text))

    def get_azure_resource(
        self, resource_name, instance_type, subscription_id, resource_group_name
    ):
        """
        Get an azure resource
        :return: The resource, if found, None if not found (http 404). Raise an
        error otherwise.
        """
        url, resource_uri = self._get_request_url(
            subscription_id, resource_group_name, instance_type, resource_name
        )
        try:
            response = requests.get(url, headers=self._get_header(resource_uri))
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            if response.status_code == 404:
                return None

            log.error(err_msg.format("Get", resource_name, e.response.text))

        if response.ok:
            return response.json()

        raise Exception(
            "Failed getting Azure resource. Resource name: "
            "'{resource_name}', type: '{instance_type}', "
            "subscription id: '{subscription_id}', "
            "resource group: '{resource_group_name}'. Http response: "
            "({status_code}) {text}".format(
                resource_name=resource_name,
                instance_type=instance_type,
                subscription_id=subscription_id,
                resource_group_name=resource_group_name,
                status_code=response.status_code,
                text=response.text,
            )
        )

    def delete_azure_resource(
        self, resource_name, instance_type, subscription_id, resource_group_name
    ):
        """
        Delete Azure resource
        :param resource_name:
        :param instance_type:
        :param subscription_id:
        :param resource_group_name:
        :return:
        """
        try:
            url, resource_uri = self._get_request_url(
                subscription_id,
                resource_group_name,
                instance_type,
                resource_name,
            )

            response = requests.delete(
                url, headers=self._get_header(resource_uri)
            )
            response.raise_for_status()

            if response.status_code != requests.codes["no_content"]:
                print(
                    '\t"{}" has been deleted from Azure "{}".'.format(
                        resource_name, resource_uri
                    )
                )
                log.info(
                    "Delete Azure resource {} response header: {}".format(
                        resource_uri, response.headers
                    )
                )

        except requests.exceptions.HTTPError as e:
            log.error(err_msg.format("Delete", resource_name, e.response.text))

    def create_azure_data_controller(
        self,
        uid,
        resource_name,
        subscription_id,
        resource_group_name,
        location,
        public_key,
        extended_properties=None,
    ):
        """
        Create Azure resource by instance
        :param public_key:
        :param uid: uid
        :param resource_name: resource name
        :param location: Azure location
        :param subscription_id: Azure subscription ID
        :param resource_group_name: resource group name
        :param extended_properties: Dict or object containing additional
        properties to be included in properties bag.
        :return:
        """

        params = {
            "location": location,
            "properties": {
                "onPremiseProperty": {"id": uid, "publicSigningKey": public_key}
            },
        }

        if extended_properties:
            params["properties"].update(extended_properties)

        url, resource_uri = self._get_request_url(
            subscription_id,
            resource_group_name,
            azure_constants.INSTANCE_TYPE_DATA_CONTROLLER,
            resource_name,
        )

        response = requests.put(
            url, headers=self._get_header(resource_uri), data=json.dumps(params)
        )
        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            response_json_string = json.loads(response.text)
            if (
                "error" in response_json_string
                and "message" in response_json_string["error"]
            ):
                self.stderr(response_json_string["error"]["message"])
            log.error(err_msg.format("Create", resource_name, e.response.text))
            raise
        print(
            '\t"{}" is uploaded to Azure "{}"'.format(
                resource_name, resource_uri
            )
        )
        log.info(
            "Create data controller {} response header: {}".format(
                resource_uri, response.headers
            )
        )

    @staticmethod
    def _get_rp_endpoint():
        endpoint = azure_constants.AZURE_ARM_URL
        if "RP_TEST_ENDPOINT" in os.environ:
            endpoint = os.environ["RP_TEST_ENDPOINT"]
        return endpoint

    def _build_dps_header(self, correlation_vector):
        access_token = acquire_token(azure_constants.AZURE_AF_SCOPE)

        request_id = str(uuid.uuid4())
        headers = {
            "Authorization": "Bearer " + access_token,
            "Content-Type": "application/json",
            "Content-Encoding": "gzip",
            "X-Request-Id": request_id,
            "X-Correlation-Vector": correlation_vector,
        }
        log.info(
            "Usage upload correlation_vector: {}, request_id: {}".format(
                correlation_vector, request_id
            )
        )
        return headers

    def _get_header(self, resource_uri):
        request_id = str(uuid.uuid4())
        log.info(
            "Resource uri: {}, request_id: {}".format(resource_uri, request_id)
        )
        return {
            "Authorization": "Bearer "
            + acquire_token(azure_constants.AZURE_ARM_SCOPE),
            "Content-Type": "application/json",
            "x-ms-client-request-id": request_id,
            "x-ms-return-client-request-id": "true",
        }

    def _get_request_url(
        self, subscription_id, resource_group_name, instance_type, resource_name
    ):
        resource_uri = azure_constants.RESOURCE_URI.format(
            subscription_id, resource_group_name, instance_type, resource_name
        )

        api_version = azure_constants.API_VERSION

        if instance_type == INSTANCE_TYPE_SQL:
            api_version = azure_constants.API_VERSION
        elif instance_type == INSTANCE_TYPE_POSTGRES:
            api_version = azure_constants.PG_API_VERSION

        return (
            self._get_rp_endpoint()
            + resource_uri
            + azure_constants.AZURE_ARM_API_VERSION_STR
            + api_version
        ), resource_uri

    @staticmethod
    def _post(url, body, headers):
        response = requests.post(url, data=body, headers=headers)

        try:
            response.raise_for_status()
        except HTTPError as ex:
            if response.status_code == http_status_codes.request_timeout:
                raise RequestTimeoutError(ex)
            elif response.status_code >= 500:
                raise ServerError(ex)
            else:
                raise

        return response

    def upload_usages_dps(
        self,
        cluster_id,
        correlation_vector,
        name,
        subscription_id,
        resource_group_name,
        location,
        connection_mode,
        infrastructure,
        timestamp,
        usages,
        signature,
    ):
        import base64

        blob = {
            "requestType": "usageUpload",
            "clusterId": cluster_id,
            "name": name,
            "subscriptionId": subscription_id,
            "resourceGroup": resource_group_name,
            "location": location,
            "connectivityMode": connection_mode,
            "infrastructure": infrastructure,
            "uploadRequest": {
                "exportType": "usages",
                "dataTimestamp": timestamp,
                # Sort by keys to retain the same order as originally signed.
                "data": json.dumps(usages, sort_keys=True).replace(" ", ""),
                "signature": signature,
            },
        }

        data_base64 = base64.b64encode(json.dumps(blob).encode("utf-8"))
        headers = self._build_dps_header(correlation_vector)
        url = (
            "https://san-af-{}-prod.azurewebsites.net/api/subscriptions"
            "/{}/resourcegroups/{}/providers"
            "/Microsoft.AzureArcData/dataControllers"
            "/{}?api-version=2022-03-01".format(
                location, subscription_id, resource_group_name, name
            )
        )

        body = (
            b'{"$schema": "https://microsoft.azuredata.com/azurearc/pipeline'
            b'/usagerecordsrequest.03-2022.schema.json","blob": "'
            + data_base64
            + b'"}'
        )

        log.info("Usage upload request_url: {}".format(url))

        response = retry(
            lambda: self._post(url, body, headers),
            retry_count=CONNECTION_RETRY_ATTEMPTS,
            retry_delay=RETRY_INTERVAL,
            retry_method="upload usages dps",
            retry_on_exceptions=(
                NewConnectionError,
                MaxRetryError,
                TimeoutError,
                RequestTimeoutError,
                ServerError,
            ),
        )

        if response.ok:
            success_msg = "Uploaded {} usage records to Azure {}.".format(
                len(usages), url
            )
            print("\t" + success_msg)
            log.info(success_msg)
            if response.headers:
                log.info(
                    "Usage upload response header: {}".format(response.headers)
                )
            return True
        else:
            return False

    def populate_sql_properties(self, params, extended_properties):
        """
        Populate sql instance properties.
        :param params: Add sql specific properties here.
        :param extended_properties: Extract sql specific properties from this.
        """
        tier = _.get(extended_properties, "k8sRaw.spec.tier")
        license_type = _.get(extended_properties, "k8sRaw.spec.licenseType")
        skuName = SQL_MI_SKU_NAME_VCORE

        sku = {"name": skuName, "tier": format_sqlmi_tier_for_azure(tier)}

        params["sku"] = sku
        params["properties"][
            "licenseType"
        ] = format_sqlmi_license_type_for_azure(license_type)

    def get_generic_azure_resource(
        self,
        subscription,
        resource_provider_namespace,
        resource_type,
        resource_group_name,
        resource_name,
        api_version,
    ):
        """
        Get a generic azure resource using AzureCliCredential and ResourceManagementClient
        """

        arm_id = f"/subscriptions/{subscription}/resourcegroups/{resource_group_name}/providers/{resource_provider_namespace}/{resource_type}/{resource_name}"
        resource = self.get_generic_azure_resource_by_id(arm_id, api_version)

        return resource

    def get_generic_azure_resource_by_id(
        self,
        resource_id,
        api_version,
    ):
        """
        Get a generic azure resource using AzureCliCredential and ResourceManagementClient
        """

        if not is_valid_resource_id(resource_id):
            raise ValidationError(
                f"Unable to get Azure resource. Invalid resource id: '{resource_id}'"
            )

        parsed_id = parse_resource_id(resource_id)

        credential = AzureCliCredential()
        resource_client = ResourceManagementClient(
            credential, parsed_id["subscription"]
        )

        log.debug(
            f"Getting Azure resource: '{resource_id}', api version: '{api_version}'"
        )
        resource = resource_client.resources.get_by_id(
            resource_id, api_version=api_version
        )

        return resource

    def get_first_extension_id_from_custom_location(
        self,
        custom_location_id,
        extension_type,
    ):
        """
        Get the first extension id match (given an extension type) from the custom location.

        :param custom_location_id: The custom location ARM id.
        :param extension_type: The extension type (e.g 'microsoft.arcdataservices').
        :returns: The first extension id matching the extension type.
        """

        arm_id = parse_resource_id(custom_location_id)
        resource_group_name = arm_id["resource_group"]
        resource_name = arm_id["resource_name"]
        subscription = arm_id["subscription"]

        credential = AzureCliCredential()
        client = CustomLocations(credential, subscription)
        enabled_resource_types = (
            client.custom_locations.list_enabled_resource_types(
                resource_group_name=resource_group_name,
                resource_name=resource_name,
            )
        )

        log.debug(
            f"Getting extension of type '{extension_type}' from custom location '{custom_location_id}'"
        )

        for enabled_resource_type in enabled_resource_types:
            et = enabled_resource_type.extension_type
            if et.lower() == extension_type.lower():
                log.debug(
                    f"Found extension id ({enabled_resource_type.cluster_extension_id}) for custom location ({custom_location_id})."
                )
                return enabled_resource_type.cluster_extension_id

        log.warning(
            f"Extension of type '{extension_type}'' not found in custom location '{custom_location_id}'"
        )

    def get_bootstrapper_extension_id_from_custom_location(
        self, custom_location_id
    ):
        """
        Get the first bootstrapper extension id from the custom location.

        :param custom_location_id: The custom location ARM id.
        :returns: The first extension id matching the extension type.
        """

        if not is_valid_resource_id(custom_location_id):
            raise ValidationError(
                f"Found invalid custom location ARM id: '{custom_location_id}'"
            )

        extension_id = self.get_first_extension_id_from_custom_location(
            custom_location_id=custom_location_id,
            extension_type="microsoft.arcdataservices",
        )

        if not extension_id:
            raise ResourceNotFoundError(
                "Unable to find bootstrapper extension resource for custom location '{custom_location_id}'"
            )

        return extension_id

    def get_extension_resource(self, extension_resource_id):
        """
        Given an extension resource id, return the generic azure resource.
        """

        log.debug(f"Getting bootstrapper extension Azure resource")

        resource = self.get_generic_azure_resource_by_id(
            resource_id=extension_resource_id,
            api_version=EXTENSION_API_VERSION,
        )

        return resource

    def get_extension_identity(self, custom_location_id):
        """
        Given a custom location id, get the principal id of the bootstrapper's identity.
        """

        log.debug(f"Data controller's custom location id: {custom_location_id}")

        extension_resource_id = (
            self.get_bootstrapper_extension_id_from_custom_location(
                custom_location_id
            )
        )
        extension = self.get_extension_resource(extension_resource_id)
        extension_identity_principal_id = extension.identity.principal_id

        return extension_identity_principal_id

    def create_or_update_generic_azure_resource(
        self,
        subscription,
        resource_provider_namespace,
        resource_type,
        resource_group_name,
        resource_name,
        api_version,
        parameters,
        wait_for_response=True,
        timeout=None,
    ):
        """
        Create or update a generic azure resource using AzureCliCredential and ResourceManagementClient
        """

        credential = AzureCliCredential()
        resource_client = ResourceManagementClient(credential, subscription)
        arm_id = f"/subscriptions/{subscription}/resourcegroups/{resource_group_name}/providers/{resource_provider_namespace}/{resource_type}/{resource_name}"

        log.debug(f"Create or update azure resource: {arm_id}")

        try:
            response = resource_client.resources.begin_create_or_update(
                resource_group_name=resource_group_name,
                resource_provider_namespace=resource_provider_namespace,
                resource_type=resource_type,
                resource_name=resource_name,
                api_version=api_version,
                parameters=parameters,
                parent_resource_path="",
            )

            if not wait_for_response:
                return response

            response.wait(timeout)

            if not response.done():
                raise AzureResponseError(
                    f"Create or update Azure resource request timed out ({arm_id})."
                )

            return response.result()

        except HttpResponseError as ex:
            raise AzureResponseError(
                f"Failed creating or updating Azure resource ({arm_id}).{os.linesep}{ex.message}"
            ) from ex
        except Exception as ex:
            raise AzureResponseError(
                f"Failed creating or updating Azure resource ({arm_id}).{os.linesep}{ex}"
            ) from ex

    def has_role_assignment(
        self,
        identity_principal_id,
        resource_group_name,
        role_id,
        role_description,
    ):

        """
        Check if a role (role_id) is assigned to identity_principal_id with resource group scope.
        """
        (
            login_credentials,
            subscription_id,
            tenant_id,
        ) = get_cli_profile().get_login_credentials()

        authorization_client = AuthorizationManagementClient(
            login_credentials, subscription_id
        )

        log.debug(
            f"Checking if role id '{role_id}' ({role_description}) is assigned to principal id {identity_principal_id} at resource group ({resource_group_name}) scope"
        )

        role_assignments = (
            authorization_client.role_assignments.list_for_resource_group(
                resource_group_name,
                filter=f"assignedTo('{identity_principal_id}')",
            )
        )

        for role_assignment in role_assignments:
            role_definition_id = role_assignment.role_definition_id

            if role_definition_id.lower().endswith(role_id):
                log.debug(
                    f"Role assignment found. Role id '{role_id}' ({role_description}) is assigned to principal id {identity_principal_id} at resource group ({resource_group_name}) scope"
                )
                return True

        log.debug(
            f"Role assignment NOT found. Role id '{role_id}' ({role_description}) is NOT assigned to principal id {identity_principal_id} at resource group ({resource_group_name}) scope"
        )

        return False

    def create_role_assignment(
        self,
        identity_principal_id,
        resource_group_name,
        role_id,
        role_description,
    ):
        """
        Create a role assignment.
        :param identity_principal_id: The identity principal we are assigning the role to.
        :param resource_group_name: The resource group to scope the assignment to.
        :param role_id: The role id to assign.
        :param role_description: The role description.
        :raises: AzureResponseError: If there is an error creating the role assignment.
        """

        (
            login_credentials,
            subscription,
            tenant_id,
        ) = get_cli_profile().get_login_credentials()

        authorization_client = AuthorizationManagementClient(
            login_credentials, subscription
        )

        scope = f"/subscriptions/{subscription}/resourceGroups/{resource_group_name}"
        role_assignment_name = uuid.uuid4()

        params = {
            "properties": {
                "roleDefinitionId": f"/subscriptions/{subscription}/providers/Microsoft.Authorization/roleDefinitions/{role_id}",
                "principalId": identity_principal_id,
            }
        }

        log.debug(
            f"Creating role assignment. Role assignment name: '{role_assignment_name}'', scope: '{scope}', role id: '{role_id}' ({role_description})"
        )

        try:
            authorization_client.role_assignments.create(
                scope, role_assignment_name, params
            )
        except CloudError as ex:
            error_msg = f"Failed to create role assignment. Role id: '{role_id}' ({role_description}), scope: '{scope}', identity principal: {identity_principal_id}. Error: {ex}"
            raise AzureResponseError(error_msg) from ex
