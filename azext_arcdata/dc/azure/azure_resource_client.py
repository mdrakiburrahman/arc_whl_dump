# ------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# ------------------------------------------------------------------------------

from azext_arcdata.kubernetes_sdk.HttpCodes import HTTPCodes
from . import constants as azure_constants
from azext_arcdata.dc.azure.ad_auth_util import acquire_token
from azext_arcdata.dc.azure.constants import (
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
    ArcError,
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
        params = {
            "location": location,
            "properties": {"dataControllerId": data_controller_name},
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

        raise ArcError(
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
                text=response.text
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
            "/{}?api-version=2021-08-01".format(
                location, subscription_id, resource_group_name, name
            )
        )

        body = (
            b'{"$schema": "https://microsoft.azuredata.com/azurearc/pipeline'
            b'/usagerecordsrequest.06-2021.schema.json","blob": "'
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
