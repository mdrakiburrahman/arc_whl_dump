# ------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# ------------------------------------------------------------------------------

import os

BASE = os.path.dirname(os.path.realpath(__file__))
"""
Base directory
"""

TEMPLATE_DIR = os.path.join(BASE, "templates")
"""
Custom resource definition directory
"""

DATA_CONTROLLER_SPEC = os.path.join(
    TEMPLATE_DIR, "dc_onPrem_default_properties.json"
)
"""
File location for data controller SPEC.
"""

DATA_CONTROLLER_SPEC_AKS = os.path.join(
    TEMPLATE_DIR, "dc_AKS_default_properties.json"
)
"""
File location for data controller SPEC.
"""

SQLMI_SPEC = os.path.join(TEMPLATE_DIR, "sqlmi_default_properties.json")
"""
File location for SQLMI SPEC.
"""
