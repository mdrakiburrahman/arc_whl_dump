# ------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# ------------------------------------------------------------------------------


def validate_mutually_exclusive_direct_indirect(
    namespace, required_direct=None, direct_only=None, ignore_direct=None
):
    """
    Common direct/indirect argument validations that can be applied across
    different command groups.

    :param namespace: The argument namespace map.
    :param required_direct: Optional required arguments for direct mode.
    :param direct_only: Optional direct mode only arguments.
    :raises ValueError
    """

    # -- mutually exclusive --
    if namespace.use_k8s:
        ignore_direct = ignore_direct or []
        msg = (
            "Cannot specify '--use-k8s' with direct mode only "
            "arguments: {args}."
        )
        included = direct_only or []

        if (
            namespace.resource_group
            and "--resource-group/-g" not in ignore_direct
        ):
            included.append("--resource-group/-g")

        if included:
            raise ValueError(msg.format(args=", ".join(included)))

    if not namespace.use_k8s and namespace.namespace:
        raise ValueError(
            "Cannot specify' --k8s-namespace/-k ' without '--use-k8s'. "
            "The ' --k8s-namespace/-k' is only available for indirect mode."
        )

    # -- direct --
    if not namespace.use_k8s:
        msg = "The following arguments are required: {missing} for direct mode."
        missing = required_direct or []

        # if not namespace.name:
        #    missing.append("--name/-n")

        if not namespace.resource_group:
            missing.append("--resource-group/-g")

        # [--subscription] is handled differently, so omit check as required

        if missing:
            raise ValueError(msg.format(missing=", ".join(missing)))

    # Check the forbidden flags
    #
    forbidden_list = {}
    if hasattr(namespace, "noexternal_endpoint"):
        forbidden_list["--no-external-endpoint"] = namespace.noexternal_endpoint
    if hasattr(namespace, "certificate_public_key_file"):
        forbidden_list[
            "--cert-public-key-file"
        ] = namespace.certificate_public_key_file
    if hasattr(namespace, "certificate_private_key_file"):
        forbidden_list[
            "--cert-private-key-file"
        ] = namespace.certificate_private_key_file
    if hasattr(namespace, "service_certificate_secret"):
        forbidden_list[
            "--service-cert-secret"
        ] = namespace.service_certificate_secret
    if hasattr(namespace, "admin_login_secret"):
        forbidden_list["--admin-login-secret"] = namespace.admin_login_secret
    if hasattr(namespace, "labels"):
        forbidden_list["--labels"] = namespace.labels
    if hasattr(namespace, "annotation"):
        forbidden_list["--annotations"] = namespace.annotations
    if hasattr(namespace, "service_labels"):
        forbidden_list["--service-labels"] = namespace.service_labels
    if hasattr(namespace, "service_annotations"):
        forbidden_list["--service-annotations"] = namespace.service_annotations
    if hasattr(namespace, "collation"):
        forbidden_list["--collation"] = namespace.collation
    if hasattr(namespace, "language"):
        forbidden_list["--language"] = namespace.language
    if hasattr(namespace, "agent_enabled"):
        forbidden_list["--agent-enabled"] = namespace.agent_enabled
    if hasattr(namespace, "trace_flags"):
        forbidden_list["--trace-flags"] = namespace.trace_flags
    if hasattr(namespace, "time_zone"):
        forbidden_list["--time-zone"] = namespace.time_zone
    if hasattr(namespace, "retention_days"):
        forbidden_list["--retention-days"] = namespace.retention_days

    direct_mode_forbid_list = []
    for flag in forbidden_list:
        if forbidden_list[flag]:
            direct_mode_forbid_list.append(flag)

    if not namespace.use_k8s and direct_mode_forbid_list:
        raise ValueError(
            "Cannot specify {0} without '--use-k8s'. "
            "The {0} is only available for indirect mode.".format(
                direct_mode_forbid_list
            )
        )
