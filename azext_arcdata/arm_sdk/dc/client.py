# ------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# ------------------------------------------------------------------------------

from azext_arcdata.arm_sdk.azure.azure_resource_client import (
    AzureResourceClient,
)
from azext_arcdata.arm_sdk.azure import constants as azure_constants
from azext_arcdata.core.cli_client import CliClient
from azext_arcdata.core.util import retry
from urllib3.exceptions import NewConnectionError, MaxRetryError
from requests.exceptions import ConnectionError
from knack.log import get_logger

import os
import pydash as _

CONNECTION_RETRY_ATTEMPTS = 12
DELETE_CLUSTER_TIMEOUT_SECONDS = 300
RETRY_INTERVAL = 5
UPDATE_INTERVAL = (15 * 60) / RETRY_INTERVAL
SCRIPT_PATH = os.path.dirname(os.path.realpath(__file__))

logger = get_logger(__name__)


def beget(az_cli, kwargs):
    """Client factory"""
    return DataCtrClientMixin(az_cli, kwargs)


class DataCtrClientMixin(CliClient):
    def __init__(self, az_cli, kwargs):
        super(DataCtrClientMixin, self).__init__(
            az_cli, kwargs, check_namespace=None
        )
        self._azure_resource_client = AzureResourceClient()

    @property
    def azure_resource_client(self):
        return self._azure_resource_client

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
