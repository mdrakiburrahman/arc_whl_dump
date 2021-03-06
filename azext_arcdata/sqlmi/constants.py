# ------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# ------------------------------------------------------------------------------

import os

from azext_arcdata.core.constants import ARC_API_V1BETA2, ARC_API_V5

RESOURCE_KIND = "SqlManagedInstance"
"""
Defines the Kubernetes custom resource kind.
"""

RESOURCE_KIND_PLURAL = "sqlmanagedinstances"
"""
Defines the plural name.
"""

API_GROUP = "sql.arcdata.microsoft.com"
"""
Defines the API group.
"""

API_VERSION = ARC_API_V5
"""
Defines the API version.
"""

SQLMI_COMMON_API_KWARGS = {
    "group": API_GROUP,
    "version": API_VERSION,
    "plural": RESOURCE_KIND_PLURAL,
}

FOG_RESOURCE_KIND = "FailoverGroup"

FOG_RESOURCE_KIND_PLURAL = "failovergroups"

FOG_API_GROUP = "sql.arcdata.microsoft.com"

FOG_API_VERSION = ARC_API_V1BETA2

# ------------------------------------------------------------------------------
# SQL server related constants
# ------------------------------------------------------------------------------
SQLMI_PASSWORD_MIN_LENGTH = 8
SQLMI_PASSWORD_REQUIRED_GROUPS = 3

# ------------------------------------------------------------------------------
# SQL MI license type constansts
# ------------------------------------------------------------------------------
SQLMI_LICENSE_TYPE_BASE_PRICE = "BasePrice"
SQLMI_LICENSE_TYPE_BASE_PRICE_AZURE = (
    SQLMI_LICENSE_TYPE_BASE_PRICE  # the format expected by ARM RP
)
SQLMI_LICENSE_TYPE_LICENSE_INCLUDED = "LicenseIncluded"
SQLMI_LICENSE_TYPE_LICENSE_INCLUDED_AZURE = (
    SQLMI_LICENSE_TYPE_LICENSE_INCLUDED  # the format expected by ARM RP
)
SQLMI_LICENSE_TYPE_DISASTER_RECOVERY = "DisasterRecovery"
SQLMI_LICENSE_TYPE_DISASTER_RECOVERY_AZURE = (
    SQLMI_LICENSE_TYPE_DISASTER_RECOVERY  # the format expected by ARM RP
)
SQLMI_LICENSE_TYPES = set(
    [
        SQLMI_LICENSE_TYPE_BASE_PRICE,
        SQLMI_LICENSE_TYPE_LICENSE_INCLUDED,
        SQLMI_LICENSE_TYPE_DISASTER_RECOVERY,
    ]
)

# message to display allowed values when creating an instance
SQLMI_LICENSE_TYPE_ALLOWED_VALUES_MSG_CREATE = (
    "Allowed values are: {0}, {1}, {2}."
    "Default is {3}. The license "
    "type can be changed.".format(
        SQLMI_LICENSE_TYPE_BASE_PRICE,
        SQLMI_LICENSE_TYPE_LICENSE_INCLUDED,
        SQLMI_LICENSE_TYPE_DISASTER_RECOVERY,
        SQLMI_LICENSE_TYPE_LICENSE_INCLUDED,
    )
)

# generic message to display allowed values
SQLMI_LICENSE_TYPE_ALLOWED_VALUES_MSG = (
    "Allowed values are: {0}, {1}, {2}. "
    "Default is {1}.".format(
        SQLMI_LICENSE_TYPE_BASE_PRICE,
        SQLMI_LICENSE_TYPE_LICENSE_INCLUDED,
        SQLMI_LICENSE_TYPE_DISASTER_RECOVERY,
    )
)
SQLMI_LICENSE_TYPE_DEFAULT = SQLMI_LICENSE_TYPE_LICENSE_INCLUDED

# ------------------------------------------------------------------------------
# SQL MI tier constansts
# ------------------------------------------------------------------------------
SQLMI_TIER_GENERAL_PURPOSE = "GeneralPurpose"
SQLMI_TIER_GENERAL_PURPOSE_SHORT = "gp"
SQLMI_TIER_GENERAL_PURPOSE_AZURE = (
    SQLMI_TIER_GENERAL_PURPOSE  # the format exptected by ARM RP
)
SQLMI_TIER_GENERAL_PURPOSE_ALL = set(
    [SQLMI_TIER_GENERAL_PURPOSE, SQLMI_TIER_GENERAL_PURPOSE_SHORT]
)
SQLMI_TIER_BUSINESS_CRITICAL = "BusinessCritical"
SQLMI_TIER_BUSINESS_CRITICAL_AZURE = (
    SQLMI_TIER_BUSINESS_CRITICAL  # the format expected by ARM RP
)
SQLMI_TIER_BUSINESS_CRITICAL_SHORT = "bc"
SQLMI_TIER_BUSINESS_CRITICAL_ALL = set(
    [SQLMI_TIER_BUSINESS_CRITICAL, SQLMI_TIER_BUSINESS_CRITICAL_SHORT]
)
SQLMI_TIERS = set(
    [
        SQLMI_TIER_GENERAL_PURPOSE,
        SQLMI_TIER_BUSINESS_CRITICAL,
        SQLMI_TIER_GENERAL_PURPOSE_SHORT,
        SQLMI_TIER_BUSINESS_CRITICAL_SHORT,
    ]
)

# message to display allowed values when creating an instance
SQLMI_TIER_ALLOWED_VALUES_MSG_CREATE = (
    "Allowed values: {0} ({1} for short) "
    "or {2} ({3} for short). Default is "
    "{4}. The price tier cannot be changed.".format(
        SQLMI_TIER_BUSINESS_CRITICAL,
        SQLMI_TIER_BUSINESS_CRITICAL_SHORT,
        SQLMI_TIER_GENERAL_PURPOSE,
        SQLMI_TIER_GENERAL_PURPOSE_SHORT,
        SQLMI_TIER_GENERAL_PURPOSE,
    )
)

# generic message to display allowed values
SQLMI_TIER_ALLOWED_VALUES_MSG = (
    "Allowed values: {0} ({1} for short) or "
    "{2} ({3} for short). Default is {4}.".format(
        SQLMI_TIER_BUSINESS_CRITICAL,
        SQLMI_TIER_BUSINESS_CRITICAL_SHORT,
        SQLMI_TIER_GENERAL_PURPOSE,
        SQLMI_TIER_GENERAL_PURPOSE_SHORT,
        SQLMI_TIER_GENERAL_PURPOSE,
    )
)


SQLMI_TIER_DEFAULT = SQLMI_TIER_GENERAL_PURPOSE

# ------------------------------------------------------------------------------
# SQL MI sku constansts
# ------------------------------------------------------------------------------
SQL_MI_SKU_NAME_VCORE = "vCore"

# ------------------------------------------------------------------------------
# SQL MI settings constansts
# ------------------------------------------------------------------------------
SQLMI_AGENT_ENABLED = "sqlagent.enabled"
SQLMI_COLLATION = "collation"
SQLMI_LANGUAGE_LCID = "language.lcid"
SQLMI_TRACEFLAGS = "traceflags"
SQLMI_SETTINGS = "settings"
SQLMI_TIMEZONE = "timezone"

BASE = os.path.dirname(os.path.realpath(__file__))
"""
Base directory
"""

TEMPLATE_DIR = os.path.join(BASE, "templates")
"""
Custom resource definition directory
"""

SQLMI_SPEC = os.path.join(TEMPLATE_DIR, "sqlmi_spec.json")
"""
File location for sqlmi SPEC.
"""

SQLMI_RESTORE_TASK_SPEC = os.path.join(TEMPLATE_DIR, "sqlmi_restore_task.json")
"""
File location for sqlmi restore task SPEC.
"""

FOG_SPEC = os.path.join(TEMPLATE_DIR, "fog_spec.json")
"""
File location for fog SPEC.
"""

SQLMI_DIRECT_MODE_SPEC_MERGE = os.path.join(
    TEMPLATE_DIR, "sqlmi_default_properties_merge.json"
)
"""
File location for sqlmi direct mode SPEC output.
"""

SQLMI_DIRECT_MODE_OUTPUT_SPEC = os.path.join(
    TEMPLATE_DIR, "sqlmi_default_properties_output.json"
)
"""
File location for sqlmi direct mode SPEC output.
"""


DAG_ROLE_PRIMARY = "primary"
DAG_ROLE_SECONDARY = "secondary"
DAG_ROLE_FORCE_PRIMARY = "force-primary-allow-data-loss"
DAG_ROLE_FORCE_SECONDARY = "force-secondary"

DAG_ROLES_ALL = set(
    [
        DAG_ROLE_PRIMARY,
        DAG_ROLE_SECONDARY,
        DAG_ROLE_FORCE_PRIMARY,
        DAG_ROLE_FORCE_SECONDARY,
    ]
)

DAG_ROLES_CREATE = set(
    [
        DAG_ROLE_PRIMARY,
        DAG_ROLE_SECONDARY,
    ]
)

DAG_ROLES_UPDATE = set(
    [
        DAG_ROLE_SECONDARY,
        DAG_ROLE_FORCE_PRIMARY,
        DAG_ROLE_FORCE_SECONDARY,
    ]
)

DAG_ROLES_ALLOWED_VALUES_MSG_CREATE = (
    "Allowed values are: {0}, {1}. "
    "Role can be changed.".format(
        DAG_ROLE_PRIMARY,
        DAG_ROLE_SECONDARY,
    )
)

DAG_ROLES_ALLOWED_VALUES_MSG_UPDATE = (
    "Role can only be changed to: {0}, {1}, {2}. ".format(
        DAG_ROLE_SECONDARY,
        DAG_ROLE_FORCE_PRIMARY,
        DAG_ROLE_FORCE_SECONDARY,
    )
)
