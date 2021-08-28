# ------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# ------------------------------------------------------------------------------


def validate_copy_logs(namespace):
    if (namespace.resource_kind is None) ^ (namespace.resource_name is None):
        raise ValueError(
            "Either --resource-kind or --resource-name is not specified. They "
            "need to be provided or omitted at the same time."
        )
