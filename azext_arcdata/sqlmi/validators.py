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
    pass
    """
    required_for_direct = []
    direct_only = []

    # -- direct --
    if not namespace.use_k8s:
        if not namespace.location:
            required_for_direct.append("--location")

        if not namespace.custom_location:
            required_for_direct.append("--custom-location")

        if (
            namespace.tag_name
            and not namespace.tag_value
            or namespace.tag_value
            and not namespace.tag_name
        ):
            raise ValueError(
                "Both '[--tag-name]' and '[--tag-value]' are "
                "required as a pair."
            )

    # -- indirect --
    if namespace.use_k8s:
        if namespace.location:
            direct_only.append("--location")

        if namespace.custom_location:
            direct_only.append("--custom-location")

        if namespace.tag_name:
            direct_only.append("--tag-name")

        if namespace.tag_value:
            direct_only.append("--tag-value")

    # -- assert common indirect/direct argument combos --
    validators.validate_mutually_exclusive_direct_indirect(
        namespace, required_direct=required_for_direct, direct_only=direct_only
    )

    # -- assert something provided to run update against, need at least 1 --
    if (
        not namespace.cores_limit
        and not namespace.cores_request
        and not namespace.memory_limit
        and not namespace.memory_request
        and not namespace.dev
        and not namespace.labels
        and not namespace.annotations
        and not namespace.service_labels
        and not namespace.service_annotations
        and not namespace.agent_enabled
        and not namespace.trace_flags
        and not namespace.time_zone
        and not namespace.retention_days
        and not namespace.tag_name
        and not namespace.tag_value
    ):

        args = [
            "   --agent-enabled",
            "   --annotations",
            "   --cores-limit/c",
            "   --cores-request",
            "   --dev",
            "   --labels",
            "   --memory-limit/-m",
            "   --memory-request",
            "   --preferred-primary-replica",
            "   --primary-replica-failover-interval",
            "   --retention-days",
            "   --service-annotations",
            "   --service-labels",
            "   --tag-name",
            "   --tag-value",
            "   --time-zone",
            "   --trace-flags",
        ]
        raise ValueError(
            "Requires at least one item to update: \n{0}\n".format(
                "\n".join(args)
            )
        )
        """
