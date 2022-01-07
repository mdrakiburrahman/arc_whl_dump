# ------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# ------------------------------------------------------------------------------

from azure.cli.core.azclierror import (
    ArgumentUsageError,
    MutuallyExclusiveArgumentError,
    ValidationError,
)
import azext_arcdata.core.common_validators as validators


def force_indirect(namespace):
    namespace.use_k8s = True


def validate_copy_logs(namespace):
    if (namespace.resource_kind is None) ^ (namespace.resource_name is None):
        raise ValidationError(
            "Either --resource-kind or --resource-name is not specified. They "
            "need to be provided or omitted at the same time."
        )
    force_indirect(namespace)


def validate_create(namespace):
    required_for_direct = []
    direct_only = []
    monitoring_cert_keys = [
        "logs_ui_public_key_file",
        "logs_ui_private_key_file",
        "metrics_ui_public_key_file",
        "metrics_ui_private_key_file",
    ]

    if namespace.profile_name and namespace.path:
        raise ArgumentUsageError(
            "Cannot specify both '[--profile-name]' and '[--path]'. "
            "Specify only one."
        )

    # -- direct --
    if not namespace.use_k8s:
        if not namespace.location:
            required_for_direct.append("--location")

        if not namespace.custom_location:
            required_for_direct.append("--custom-location")
        
        for key in monitoring_cert_keys:
            if getattr(namespace, key, None):
                raise ArgumentUsageError(
                    "Cannot specify {0} in direct mode. Monitoring endpoint certificate"
                    " arguments are for indirect mode only.".format("--" + "-".join(key.split("_")))
                )

    # -- indirect --
    if namespace.use_k8s:
        # if namespace.location:
        #    direct_only.append("--location")

        if namespace.custom_location:
            direct_only.append("--custom-location")

        if namespace.auto_upload_metrics:
            direct_only.append("--auto-upload-metrics")

        if namespace.auto_upload_logs:
            direct_only.append("--auto-upload-metrics")

    # -- assert common indirect/direct argument combos --
    validators.validate_mutually_exclusive_direct_indirect(
        namespace,
        required_direct=required_for_direct,
        direct_only=direct_only,
        ignore_direct=["--resource-group/-g"],
    )


def validate_delete(namespace):
    validators.validate_mutually_exclusive_direct_indirect(namespace)


def validate_status_show(namespace):
    validators.validate_mutually_exclusive_direct_indirect(namespace)


def validate_update(namespace):
    """
    Validates the supplied arguments for 'arc dc update' command
    """

    # make sure at least one property is being updated
    if not namespace.auto_upload_logs and not namespace.auto_upload_metrics:
        raise ArgumentUsageError(
            "Either '[--auto-upload-logs]' or '[--auto-upload-metrics]' is "
            "required"
        )

    # We don't allow updating auto_upload_logs and auto_upload_metrics at the
    # same time
    if namespace.auto_upload_logs and namespace.auto_upload_metrics:
        raise MutuallyExclusiveArgumentError(
            "Only one of '[--auto-upload-logs]' or '[--auto-upload-metrics]' "
            "can be specified."
        )


def validate_upgrade(namespace):
    required_for_direct = []

    # -- direct --
    if not namespace.use_k8s:
        if not namespace.target:
            required_for_direct.append("--target")

        if not namespace.name:
            required_for_direct.append("--name")

    # -- assert common indirect/direct argument combos --
    validators.validate_mutually_exclusive_direct_indirect(
        namespace, required_direct=required_for_direct
    )
