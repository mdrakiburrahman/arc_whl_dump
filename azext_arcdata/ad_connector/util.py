# ------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# ------------------------------------------------------------------------------

from azext_arcdata.ad_connector.validators import (
    _validate_domain_name,
    _validate_netbios_domain_name,
    _validate_ip_address,
)


def _parse_realm(realm):
    if not _validate_domain_name(realm):
        raise ValueError(
            "The given realm '{}' is invalid. Realm must be a valid DNS domain name.".format(
                realm
            )
        )

    return realm.upper()


def _parse_netbios_domain_name(netbios_domain_name):
    if not netbios_domain_name:
        return

    if not _validate_netbios_domain_name(netbios_domain_name):
        raise ValueError(
            "The given NETBIOS domain name '{}' is invalid.".format(
                netbios_domain_name
            )
        )

    return netbios_domain_name.upper()


def _parse_dns_domain_name(dns_domain_name):
    if not dns_domain_name:
        return

    if not _validate_domain_name(dns_domain_name):
        raise ValueError(
            "The given DNS domain name '{}' is invalid.".format(dns_domain_name)
        )

    return dns_domain_name


def _parse_primary_domain_controller(primary_domain_controller):
    if not primary_domain_controller:
        return

    if not _validate_domain_name(primary_domain_controller):
        raise ValueError(
            "The given primary domain controller hostname '{}' is invalid.".format(
                primary_domain_controller
            )
        )

    return {"hostname": primary_domain_controller}


def _parse_secondary_domain_controllers(domain_controllers_string):
    if not domain_controllers_string:
        return []

    hostnames = domain_controllers_string.replace(" ", "").split(",")

    domain_controllers = []
    for hostname in hostnames:
        if not _validate_domain_name(hostname):
            raise ValueError(
                "One or more secondary domain controller hostnames is invalid."
            )

        domain_controllers.append({"hostname": hostname})

    return domain_controllers


def _parse_nameserver_addresses(nameserver_addresses):
    if not nameserver_addresses:
        return []

    tokens = nameserver_addresses.replace(" ", "").split(",")
    nameserver_addresses = []

    for address in tokens:
        if not _validate_ip_address(address):
            raise ValueError(
                "One or more Active Directory DNS server IP addresses are invalid."
            )

        nameserver_addresses.append(address)

    return nameserver_addresses


def _parse_num_replicas(num_replicas):
    if num_replicas is None:
        return

    try:
        num_replicas = int(num_replicas)
        assert num_replicas >= 1
        return num_replicas
    except:
        raise ValueError(
            "Invalid number of DNS replicas. --dns-replicas must be 1 or greater."
        )


def _parse_prefer_k8s_dns(prefer_k8s_dns):
    if prefer_k8s_dns is None:
        return

    prefer_k8s_dns = str(prefer_k8s_dns).lower()

    if prefer_k8s_dns not in ["true", "false"]:
        raise ValueError(
            "The allowed values for --prefer-k8s-dns are 'true' or 'false'"
        )

    return False if prefer_k8s_dns == "false" else True
