# ------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# ------------------------------------------------------------------------------

RESOURCE_PROVIDER_NAMESPACE = "Microsoft.AzureArcData"
"""
Resource provider namespace
"""

API_VERSION = "2021-08-01"
"""
DataController and MIAA Resource provider API version
"""

PG_API_VERSION = "2021-07-01-preview"
"""
Postgres Resource provider API version
"""

RESOURCE_URI = (
    "/subscriptions/{}/resourcegroups/{}/providers/Microsoft.AzureArcData/{}/{}"
)
"""
Azure Resource URI
"""

RESOURCE_TYPE_POSTGRES = "Microsoft.AzureArcData/postgresInstances"
"""
Postgres resource type
"""

RESOURCE_TYPE_SQL = "Microsoft.AzureArcData/sqlManagedInstances"
"""
SQL instance resource type
"""

RESOURCE_TYPE_DATA_CONTROLLER = "Microsoft.AzureArcData/dataControllers"
"""
Data controller Azure resource type
"""

INSTANCE_TYPE_POSTGRES = "postgresInstances"
"""
Postgres instance type
"""

INSTANCE_TYPE_SQL = "sqlManagedInstances"
"""
SQL instance type
"""

RESOURCE_KIND_DATA_CONTROLLER = "dataController"
"""
Resource kind for Arc data controller
"""

RESOURCE_KIND_POSTGRES = "PostgreSql"
"""
Resource kind for Postgres
"""

RESOURCE_KIND_SQL = "SqlManagedInstance"
"""
SQL instance resource kind
"""

INSTANCE_TYPE_DATA_CONTROLLER = "dataControllers"
"""
Hybrid data manager type
"""

METRICS_SQL_NAMESPACE = "SQL Server"
"""
SQL instance metrics namespace in Azure monitoring
"""

METRICS_POSTGRES_NAMESPACE = "Postgres"
"""
Postgres instance metrics namespace in Azure monitoring
"""

DEFAULT_NAMESPACE = "default"
"""
The default namespace in k8s
"""

DIRECT_CONNECTIVITY_MODE = "direct"
"""
The direct connectivity mode
"""

INDIRECT_CONNECTIVITY_MODE = "indirect"
"""
The indirect connectivity mode
"""

RESOURCE_TYPE_FOR_KIND = {
    RESOURCE_KIND_DATA_CONTROLLER: INSTANCE_TYPE_DATA_CONTROLLER,
    RESOURCE_KIND_SQL: INSTANCE_TYPE_SQL,
    RESOURCE_KIND_POSTGRES: INSTANCE_TYPE_POSTGRES,
}
"""
Instance type to resource type lookup
"""

RESOURCE_TYPES_OF_DATA_SERVICES = {
    INSTANCE_TYPE_SQL: RESOURCE_TYPE_SQL,
    INSTANCE_TYPE_POSTGRES: RESOURCE_TYPE_POSTGRES,
}
"""
Instance type of data service
"""

PATCH_PAYLOAD_LIMIT = 1024 * 1000
"""
Azure patch payload limit
"""

BILLING_MODEL_COMSUMPTION = "consumption"
"""
Consumption based billing model
"""

BILLING_MODEL_CAPCITY = "capacity"
"""
Capacity based billing model
"""

CLUSTER_CONNECTION_MODE_CONNECTED = "connected"
"""
Connected cluster
"""

CLUSTER_CONNECTION_MODE_DISCONNECTED = "disconnected"
"""
Disconnected cluster
"""

DEFAULT_DATA_CONTROLLER_NAME = "DataController"
"""
Default data controller name
"""

AZURE_ARM_URL = "https://management.azure.com"
"""
Azure ARM URL
"""

AZURE_ARM_API_VERSION_STR = "?api-version="
"""
Azure ARM API version string in header
"""

AAD_LOGIN_URL = "https://login.microsoftonline.com/"
"""
AAD login URL
"""

AZURE_ARM_SCOPE = ["https://management.azure.com/.default"]
"""
Azure ARM SCOPE
"""

AAD_PROFILE_FILENAME = "aad-profile.json"
"""
AAD token cache file name
"""

AZURE_AF_SCOPE = ["https://azurearcdata.billing.publiccloudapi.net/.default"]
"""
Azure ARM SCOPE
"""

SPN_ENV_KEYS = {
    "authority": "SPN_AUTHORITY",
    "tenant_id": "SPN_TENANT_ID",
    "client_id": "SPN_CLIENT_ID",
    "client_secret": "SPN_CLIENT_SECRET",
}
"""
Environment variables' name of SPN for metric upload
"""

METRICS_CONFIG_FILENAME = "metrics-config.json"
"""
Metric config file name
"""

AZURE_METRICS_SCOPE = ["https://monitoring.azure.com//.default"]
"""
Azure Custom Metrics url
"""

PUBLIC_CLOUD_LOGIN_URL = "https://login.microsoftonline.com"
"""
Azure public cloud AAD login url
"""

API_LOG = "/api/logs"
"""
Log upload api resource value
"""
