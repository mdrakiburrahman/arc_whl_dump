# coding=utf-8
# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

from knack.help_files import helps  # pylint: disable=unused-import


helps['customlocation'] = """
    type: group
    short-summary: Commands to Create, Get, List and Delete CustomLocations.
"""

helps['customlocation create'] = """
    type: command
    short-summary: Create a Custom Location.
"""

helps['customlocation update'] = """
    type: command
    short-summary: Update a Custom Location.
"""

helps['customlocation patch'] = """
    type: command
    short-summary: Patch a Custom Location.
"""

helps['customlocation list'] = """
    type: command
    short-summary: Command to list CustomLocations.
"""

helps['customlocation delete'] = """
    type: command
    short-summary: Delete a Customlocation.
"""

helps['customlocation show'] = """
    type: command
    short-summary: Get details of a Customlocation.
"""

helps['customlocation list-enabled-resource-types'] = """
    type: command
    short-summary: Get details of Enabled Resource Types for a CustomLocation.
"""
