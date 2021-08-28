# ------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# ------------------------------------------------------------------------------

import os
from azext_arcdata.core.constants import ARC_API_V1
from azext_arcdata.postgres.constants import (
    POSTGRES_SPEC,
)
from azext_arcdata.sqlmi.constants import (
    SQLMI_SPEC,
    SQLMI_RESTORE_TASK_SPEC,
    DAG_SPEC,
)

ARC_NAME = "arc"
"""
Command group constant
"""

DATA_CONTROLLER_CUSTOM_RESOURCE = "datacontroller"
"""
Name of control plane custom resource
"""

EXPORT_TASK_CUSTOM_RESOURCE = "export"
"""
Name of export task custom resource
"""

CONTROLLER_LABEL = "controller"
"""
Name of the controller app label
"""

CONTROLLER_SVC = "controller-external-svc"
"""
Name of external controller service
"""

MGMT_PROXY = "mgmtproxy-svc-external"
"""
Name of management proxy service
"""

MONITOR_PLURAL = "monitors"
"""
Plural name for Monitor custom resource.
"""

MONITOR_CRD_VERSION = ARC_API_V1
"""
Defines the kubernetes api version for Monitor CRD.
"""

MONITOR_RESOURCE = "monitorstack"
"""
Monitor resource.
"""

BASE = os.path.dirname(os.path.realpath(__file__))
"""
Base directory
"""

CONFIG_DIR = os.path.join(BASE, "deployment-configs")
"""
Config directory
"""

TEMPLATE_DIR = os.path.join(BASE, "templates")
"""
Custom resource definition directory
"""

DATA_CONTROLLER_CRD = os.path.join(TEMPLATE_DIR, "data_controller_crd.yaml")
"""
File location for control plane CRD.
"""

MONITOR_CRD = os.path.join(TEMPLATE_DIR, "monitor_crd.yaml")
"""
File location for monitor CRD.
"""

POSTGRES_CRD = os.path.join(TEMPLATE_DIR, "postgres_crd.yaml")
"""
File location for postgres CRD.
"""

SQLMI_CRD = os.path.join(TEMPLATE_DIR, "sqlmi_crd.yaml")
"""
File location for sqlmi CRD.
"""

SQLMI_RESTORE_TASK_CRD = os.path.join(
    TEMPLATE_DIR, "sqlmi_restore_task_crd.yaml"
)
"""
File location for sqlmi restore CRD.
"""

DAG_CRD = os.path.join(TEMPLATE_DIR, "dag_crd.yaml")
"""
File location for distributed AG CRD.
"""


EXPORT_TASK_CRD = os.path.join(TEMPLATE_DIR, "export-crd.yaml")
"""
File location for export task CRD.
"""

DATA_CONTROLLER_SPEC = os.path.join(TEMPLATE_DIR, "data_controller_spec.json")
"""
File location for data controller SPEC.
"""

MONITOR_SPEC = os.path.join(TEMPLATE_DIR, "monitor_spec.json")
"""
File location for monitor SPEC.
"""

EXPORT_TASK_SPEC = os.path.join(TEMPLATE_DIR, "export_task_spec.json")
"""
File location for export task SPEC.
"""


EXPORT_TASK_CRD_VERSION = ARC_API_V1
"""
Defines the kubernetes api version for Export task CRD.
"""

ARC_WEBHOOK_JOB_TEMPLATE = os.path.join(
    TEMPLATE_DIR, "arc-webhook-job.yaml.tmpl"
)
"""
File location for webhook job template
"""

ARC_WEBHOOK_ROLE_TEMPLATE = os.path.join(
    TEMPLATE_DIR, "role-arc-webhook-job.yaml.tmpl"
)
"""
File location for webhook job template
"""

ARC_WEBHOOK_RB_TEMPLATE = os.path.join(
    TEMPLATE_DIR, "rb-arc-webhook-job.yaml.tmpl"
)
"""
File location for webhook job template
"""

ARC_WEBHOOK_CR_TEMPLATE = os.path.join(TEMPLATE_DIR, "cr-arc-webhook-job.yaml.tmpl")
"""
File location for webhook job cluster role template
"""

ARC_WEBHOOK_SA_TEMPLATE = os.path.join(
    TEMPLATE_DIR, "sa-arc-webhook-job.yaml.tmpl"
)
"""
File location for webhook job service account
"""

ARC_WEBHOOK_CRB_TEMPLATE = os.path.join(
    TEMPLATE_DIR, "crb-arc-webhook-job.yaml.tmpl"
)
"""
File location for webhook job cluster role binding template
"""

ARC_WEBHOOK_SPEC_TEMPLATE = os.path.join(TEMPLATE_DIR, "test-hook.yaml")
"""
Template for the arc webhook
"""

HELP_DIR = os.path.join(CONFIG_DIR, "help")
"""
Help config directory
"""

CONTROL_CONFIG_FILENAME = "control.json"
"""
Control config file name
"""

CONFIG_FILES = [CONTROL_CONFIG_FILENAME]
"""
Array of config file names from profiles
"""

LAST_BILLING_USAGE_FILE = "usage-{}.json"
"""
Name of last usage file exported before deleting data controller
"""

LAST_USAGE_UPLOAD_FLAG = "end_usage"
"""
Key of flag in usage file indicating last usage upload
"""

EXPORT_TASK_RESOURCE_KIND = "ExportTask"
"""
Defines the export resource kind name.
"""

EXPORT_TASK_RESOURCE_KIND_PLURAL = "exporttasks"
"""
Defines the export resource kind plural name.
"""

TASK_API_GROUP = "tasks.arcdata.microsoft.com"
"""
Defines the API group.
"""

MAX_POLLING_ATTEMPTS = 12
"""
Max retry attepts to get custom resource status
"""

EXPORT_COMPLETED_STATE = "Completed"
"""
Export completed state
"""

DEFAULT_METRIC_QUERY_WINDOW_IN_MINUTE = 28
"""
Default metric query window in minute
"""

DEFAULT_LOG_QUERY_WINDOW_IN_MINUTE = 14 * 24 * 60
"""
Default log query window in minute
"""

DEFAULT_USAGE_QUERY_WINDOW_IN_MINUTE = 62 * 24 * 60
"""
Default usage query window in minute
"""

DEFAULT_QUERY_WINDOW = {
    "metrics": DEFAULT_METRIC_QUERY_WINDOW_IN_MINUTE,
    "logs": DEFAULT_LOG_QUERY_WINDOW_IN_MINUTE,
    "usage": DEFAULT_USAGE_QUERY_WINDOW_IN_MINUTE,
}

"""
Default query window for three types of data
"""

############################################################################
# Data Controller constants
############################################################################

GUID_REGEX = r"[0-9a-f]{8}\-([0-9a-f]{4}\-){3}[0-9a-f]{12}"
"""
Used to validate subscription IDs
"""

DIRECT = "direct"
"""
Direct connection mode
"""

INDIRECT = "indirect"
"""
Indirect connection mode
"""

CONNECTIVITY_TYPES = [DIRECT, INDIRECT]
"""
Supported connectivity types for data controller
"""

SUPPORTED_REGIONS = [
    "eastus",
    "eastus2",
    "centralus",
    "westeurope",
    "southeastasia",
    "westus2",
    "japaneast",
    "australiaeast",
    "koreacentral",
    "northeurope",
    "uksouth",
    "francecentral",
]
"""
Supported Azure regions for data controller. This list does not include EUAP 
regions.
"""

SUPPORTED_EUAP_REGIONS = ["eastus2euap", "centraluseuap", "eastasia"]
"""
Supported Azure EUAP regions for data controller.
"""

INFRASTRUCTURE_AWS = "aws"
INFRASTRUCTURE_GCP = "gcp"
INFRASTRUCTURE_AZURE = "azure"
INFRASTRUCTURE_ALIBABA = "alibaba"
INFRASTRUCTURE_ONPREMISES = "onpremises"
INFRASTRUCTURE_OTHER = "other"
INFRASTRUCTURE_AUTO = "auto"
INFRASTRUCTURE_PARAMETER_DEFAULT_VALUE = INFRASTRUCTURE_AUTO
# these are the allowed parameter values in the cli
INFRASTRUCTURE_PARAMETER_ALLOWED_VALUES = [
    INFRASTRUCTURE_AWS,
    INFRASTRUCTURE_GCP,
    INFRASTRUCTURE_AZURE,
    INFRASTRUCTURE_ALIBABA,
    INFRASTRUCTURE_ONPREMISES,
    INFRASTRUCTURE_OTHER,
    INFRASTRUCTURE_AUTO,
]
# these are the allowed values in the CR (different from allowed parameters, as the parameters accept "auto" which is not a valid value in the CR)
INFRASTRUCTURE_CR_ALLOWED_VALUES = [
    INFRASTRUCTURE_AWS,
    INFRASTRUCTURE_GCP,
    INFRASTRUCTURE_AZURE,
    INFRASTRUCTURE_ALIBABA,
    INFRASTRUCTURE_ONPREMISES,
    INFRASTRUCTURE_OTHER,
]

INFRASTRUCTURE_PARAMETER_INVALID_VALUE_MSG = (
    "Please input a valid infrastructure. Supported values are:"
    " " + ", ".join(INFRASTRUCTURE_PARAMETER_ALLOWED_VALUES) + "."
)

INFRASTRUCTURE_CR_INVALID_VALUE_MSG = (
    "Please input a valid infrastructure. Supported values are:"
    " " + ", ".join(INFRASTRUCTURE_CR_ALLOWED_VALUES) + "."
)

CRD_FILE_DICT = {
    "PostgreSql": POSTGRES_CRD,
    "SqlManagedInstance": SQLMI_CRD,
    "SqlManagedInstanceRestoreTask": SQLMI_RESTORE_TASK_CRD,
    "ExportTask": EXPORT_TASK_CRD,
    "Dag": DAG_CRD,
    "Monitor": MONITOR_CRD,
    "DataController": DATA_CONTROLLER_CRD
}

SPEC_FILE_DICT = {
    "PostgreSql": POSTGRES_SPEC,
    "SqlManagedInstance": SQLMI_SPEC,
    "SqlManagedInstanceRestoreTask": SQLMI_RESTORE_TASK_SPEC,
    "ExportTask": EXPORT_TASK_SPEC,
    "Dag": DAG_SPEC,
    "Monitor": MONITOR_SPEC,
    "DataController": DATA_CONTROLLER_SPEC
}
