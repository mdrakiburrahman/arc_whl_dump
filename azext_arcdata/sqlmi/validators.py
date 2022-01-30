# ------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# ------------------------------------------------------------------------------

import azext_arcdata.core.common_validators as validators


def validate_create(namespace):
    required_for_direct = []

    # -- direct --
    if not namespace.use_k8s:
        if not namespace.location:
            required_for_direct.append("--location")

        if not namespace.custom_location:
            required_for_direct.append("--custom-location")

    # -- assert common mutually exclusive arg combos if using indirect/direct --
    validators.validate_mutually_exclusive_direct_indirect(
        namespace, required_direct=required_for_direct
    )

    # -- assert mutually exclusive direct args combos if using indirect --
    if namespace.use_k8s:
        msg = (
            "Cannot specify both '{args}' and '--use-k8s'. The '{args}' is "
            "only available for direct mode."
        )
        direct_only = []
        if namespace.location:
            direct_only.append("--location")

        if namespace.custom_location:
            direct_only.append("--custom-location")

        if direct_only:
            raise ValueError(msg.format(args=", ".join(direct_only)))


def validate_delete(namespace):
    validators.validate_mutually_exclusive_direct_indirect(namespace)


def validate_show(namespace):
    validators.validate_mutually_exclusive_direct_indirect(namespace)


def validate_list(namespace):
    validators.validate_mutually_exclusive_direct_indirect(namespace)


def validate_upgrade(namespace):
    validators.validate_mutually_exclusive_direct_indirect(namespace)


def validate_update(namespace):
    required_for_direct = []
    direct_only = []

    # -- direct --
    if not namespace.use_k8s:
        if not namespace.resource_group:
            required_for_direct.append("--resource-group")

    # -- indirect --
    if namespace.use_k8s:
        if namespace.resource_group:
            direct_only.append("--resource-group")

    # -- assert common indirect/direct argument combos --
    validators.validate_mutually_exclusive_direct_indirect(
        namespace, required_direct=required_for_direct, direct_only=direct_only
    )
