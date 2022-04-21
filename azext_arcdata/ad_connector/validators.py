# ------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# ------------------------------------------------------------------------------

import azext_arcdata.core.common_validators as validators
import ipaddress


def validate_mutually_exclusive_direct_indirect_args(namespace):
    required_for_direct = []
    direct_only = []

    # -- direct --
    if not namespace.use_k8s:
        if not namespace.resource_group:
            required_for_direct.append("--resource-group")
        if not namespace.data_controller_name:
            required_for_direct.append("--data-controller-name")

    # -- indirect --
    if namespace.use_k8s:
        if namespace.resource_group:
            direct_only.append("--resource-group")
        if namespace.data_controller_name:
            direct_only.append("--data-controller-name")

    # -- assert common indirect/direct argument combos --
    validators.validate_mutually_exclusive_direct_indirect(
        namespace, required_direct=required_for_direct, direct_only=direct_only
    )


def _validate_domain_name(domain_name):
    fqdn_min_length = 2
    fqdn_max_length = 255
    label_max_length = 63
    disallowed_chars = [
        ",",
        "~",
        ":",
        "!",
        "@",
        "#",
        "$",
        "%",
        "^",
        "&",
        "'",
        "(",
        ")",
        "{",
        "}",
        "_",
        " ",
    ]

    domain_name_len = len(domain_name)
    if domain_name_len < fqdn_min_length or domain_name_len > fqdn_max_length:
        return False

    for c in domain_name:
        if c in disallowed_chars:
            return False

    if domain_name[0] == ".":
        return False

    for label in domain_name.split("."):
        if len(label) > label_max_length:
            return False

    return True


def _validate_netbios_domain_name(domain_name):
    min_length = 1
    max_length = 15
    disallowed_chars = ["\\", "/", ":", "*", "?", '"', "<", ">", "|"]

    domain_name_len = len(domain_name)
    if domain_name_len < min_length or domain_name_len > max_length:
        return False

    for c in domain_name:
        if c in disallowed_chars:
            return False

    if domain_name[0] == ".":
        return False

    return True


def _validate_ip_address(address):
    try:
        ipaddress.ip_address(address)
        return True
    except:
        return False
