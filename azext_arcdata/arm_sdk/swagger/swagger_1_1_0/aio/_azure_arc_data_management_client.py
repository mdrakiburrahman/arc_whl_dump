# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator (autorest: 3.8.3, generator: @autorest/python@5.16.0)
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from copy import deepcopy
from typing import Any, Awaitable

from msrest import Deserializer, Serializer

from azure.core import AsyncPipelineClient
from azure.core.rest import AsyncHttpResponse, HttpRequest

from .. import models
from ._configuration import AzureArcDataManagementClientConfiguration
from .operations import (
    ActiveDirectoryConnectorsOperations,
    DataControllersOperations,
    Operations,
    PostgresInstancesOperations,
    SqlManagedInstancesOperations,
    SqlServerInstancesOperations,
)


class AzureArcDataManagementClient:
    """The AzureArcData management API provides a RESTful set of web APIs to manage Azure Data
    Services on Azure Arc Resources.

    :ivar operations: Operations operations
    :vartype operations: azure_arc_data_management_client.aio.operations.Operations
    :ivar sql_managed_instances: SqlManagedInstancesOperations operations
    :vartype sql_managed_instances:
     azure_arc_data_management_client.aio.operations.SqlManagedInstancesOperations
    :ivar sql_server_instances: SqlServerInstancesOperations operations
    :vartype sql_server_instances:
     azure_arc_data_management_client.aio.operations.SqlServerInstancesOperations
    :ivar data_controllers: DataControllersOperations operations
    :vartype data_controllers:
     azure_arc_data_management_client.aio.operations.DataControllersOperations
    :ivar active_directory_connectors: ActiveDirectoryConnectorsOperations operations
    :vartype active_directory_connectors:
     azure_arc_data_management_client.aio.operations.ActiveDirectoryConnectorsOperations
    :ivar postgres_instances: PostgresInstancesOperations operations
    :vartype postgres_instances:
     azure_arc_data_management_client.aio.operations.PostgresInstancesOperations
    :param subscription_id: The ID of the Azure subscription.
    :type subscription_id: str
    :param base_url: Service URL. Default value is "https://management.azure.com".
    :type base_url: str
    :keyword api_version: Api Version. Default value is "2022-03-01-preview". Note that overriding
     this default value may result in unsupported behavior.
    :paramtype api_version: str
    :keyword int polling_interval: Default waiting time between two polls for LRO operations if no
     Retry-After header is present.
    """

    def __init__(
        self,
        subscription_id: str,
        base_url: str = "https://management.azure.com",
        **kwargs: Any,
    ) -> None:
        self._config = AzureArcDataManagementClientConfiguration(
            subscription_id=subscription_id, **kwargs
        )
        self._client = AsyncPipelineClient(
            base_url=base_url, config=self._config, **kwargs
        )

        client_models = {
            k: v for k, v in models.__dict__.items() if isinstance(v, type)
        }
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)
        self._serialize.client_side_validation = False
        self.operations = Operations(
            self._client, self._config, self._serialize, self._deserialize
        )
        self.sql_managed_instances = SqlManagedInstancesOperations(
            self._client, self._config, self._serialize, self._deserialize
        )
        self.sql_server_instances = SqlServerInstancesOperations(
            self._client, self._config, self._serialize, self._deserialize
        )
        self.data_controllers = DataControllersOperations(
            self._client, self._config, self._serialize, self._deserialize
        )
        self.active_directory_connectors = ActiveDirectoryConnectorsOperations(
            self._client, self._config, self._serialize, self._deserialize
        )
        self.postgres_instances = PostgresInstancesOperations(
            self._client, self._config, self._serialize, self._deserialize
        )

    def _send_request(
        self, request: HttpRequest, **kwargs: Any
    ) -> Awaitable[AsyncHttpResponse]:
        """Runs the network request through the client's chained policies.

        >>> from azure.core.rest import HttpRequest
        >>> request = HttpRequest("GET", "https://www.example.org/")
        <HttpRequest [GET], url: 'https://www.example.org/'>
        >>> response = await client._send_request(request)
        <AsyncHttpResponse: 200 OK>

        For more information on this code flow, see https://aka.ms/azsdk/python/protocol/quickstart

        :param request: The network request you want to make. Required.
        :type request: ~azure.core.rest.HttpRequest
        :keyword bool stream: Whether the response payload will be streamed. Defaults to False.
        :return: The response of your network call. Does not do error handling on your response.
        :rtype: ~azure.core.rest.AsyncHttpResponse
        """

        request_copy = deepcopy(request)
        request_copy.url = self._client.format_url(request_copy.url)
        return self._client.send_request(request_copy, **kwargs)

    async def close(self) -> None:
        await self._client.close()

    async def __aenter__(self) -> "AzureArcDataManagementClient":
        await self._client.__aenter__()
        return self

    async def __aexit__(self, *exc_details) -> None:
        await self._client.__aexit__(*exc_details)
