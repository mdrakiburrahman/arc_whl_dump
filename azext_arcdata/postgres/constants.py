# ------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# -----------------------------------------------------------------------------

from azext_arcdata.kubernetes_sdk.models.kube_quantity import KubeQuantity
from azext_arcdata.core.constants import ARC_API_V1BETA1
import os

RESOURCE_KIND = "PostgreSql"
"""
Kubernetes resource kind for postgres.
"""

API_GROUP = "arcdata.microsoft.com"
"""
Defines the API group.
"""

API_VERSION = ARC_API_V1BETA1
"""
Defines the API version.
"""

COMMAND_UNIMPLEMENTED = "This command is currently unimplemented."
"""
Unimplemented response.
"""

SUPPORTED_ENGINE_VERSIONS = [11, 12]
"""
Supported engine versions.
"""

DEFAULT_ENGINE_VERSION = 12
"""
Default engine versions.
"""

# ------------------------------------------------------------------------------
# Postgres resource constants
# ------------------------------------------------------------------------------
POSTGRES_MIN_MEMORY_SIZE = KubeQuantity("256Mi")
POSTGRES_MIN_CORES_SIZE = KubeQuantity("1")

BASE = os.path.dirname(os.path.realpath(__file__))
"""
Base directory
"""

TEMPLATE_DIR = os.path.join(BASE, "templates")
"""
Custom resource definition directory
"""

POSTGRES_SPEC = os.path.join(TEMPLATE_DIR, "postgresql-spec.json")
"""
File location for postgres SPEC .
"""
