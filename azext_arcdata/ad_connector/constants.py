# ------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# ------------------------------------------------------------------------------

from azext_arcdata.core.constants import ARC_API_V1BETA1

AD_CONNECTOR_RESOURCE_KIND = "ActiveDirectoryConnector"
"""
Defines the Kubernetes custom resource kind for active directory connectors
"""
AD_CONNECTOR_RESOURCE_KIND_PLURAL = "activedirectoryconnectors"
"""
Defines the plural name for active directory connectors
"""
AD_CONNECTOR_API_GROUP = "arcdata.microsoft.com"
"""
The Kubernetes group for AD connector
"""
AD_CONNECTOR_API_VERSION = ARC_API_V1BETA1
"""
The Kubernetes version for AD connector resources.
"""
