# ------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# ------------------------------------------------------------------------------
from azext_arcdata.ad_connector.exceptions import ADConnectorError
from azext_arcdata.ad_connector.util import (
    _parse_dns_domain_name,
    _parse_netbios_domain_name,
    _parse_num_replicas,
    _parse_prefer_k8s_dns,
    _parse_realm,
    _parse_nameserver_addresses,
    _parse_primary_domain_controller,
    _parse_secondary_domain_controllers,
)
from azext_arcdata.kubernetes_sdk.dc.constants import (
    ACTIVE_DIRECTORY_CONNECTOR_CRD_NAME,
)
from azext_arcdata.core.constants import USE_K8S_EXCEPTION_TEXT

from azext_arcdata.core.util import (
    check_and_set_kubectl_context,
    retry,
)
from azext_arcdata.kubernetes_sdk.client import (
    K8sApiException,
    KubernetesClient,
    KubernetesError,
    http_status_codes,
)
from azext_arcdata.kubernetes_sdk.models.custom_resource import CustomResource
from azext_arcdata.ad_connector.models.ad_connector_cr_model import (
    ActiveDirectoryConnectorCustomResource,
)
from azext_arcdata.ad_connector.constants import (
    AD_CONNECTOR_RESOURCE_KIND,
    AD_CONNECTOR_RESOURCE_KIND_PLURAL,
    AD_CONNECTOR_API_GROUP,
    AD_CONNECTOR_API_VERSION,
)
from humanfriendly.terminal.spinners import AutomaticSpinner
from knack.cli import CLIError
from knack.log import get_logger
from urllib3.exceptions import MaxRetryError, NewConnectionError

logger = get_logger(__name__)


def ad_connector_create(
    client,
    name,
    realm,
    nameserver_addresses,
    primary_domain_controller=None,
    secondary_domain_controllers=None,
    netbios_domain_name=None,
    dns_domain_name=None,
    num_dns_replicas=1,
    prefer_k8s_dns="true",
    # -- indirect --
    namespace=None,
    use_k8s=None,
    # -- direct --
    data_controller_name=None,
    resource_group=None,
):
    try:
        if not use_k8s:
            raise ValueError(USE_K8S_EXCEPTION_TEXT)

        check_and_set_kubectl_context()
        namespace = namespace or client.namespace

        realm = _parse_realm(realm)
        nameserver_addresses = _parse_nameserver_addresses(nameserver_addresses)

        primary_domain_controller = _parse_primary_domain_controller(
            primary_domain_controller
        )
        secondary_domain_controllers = _parse_secondary_domain_controllers(
            secondary_domain_controllers
        )
        netbios_domain_name = _parse_netbios_domain_name(netbios_domain_name)
        dns_domain_name = _parse_dns_domain_name(dns_domain_name)
        prefer_k8s_dns = _parse_prefer_k8s_dns(prefer_k8s_dns)
        num_dns_replicas = _parse_num_replicas(num_dns_replicas)

        custom_object_exists = retry(
            lambda: client.apis.kubernetes.namespaced_custom_object_exists(
                name,
                namespace,
                group=AD_CONNECTOR_API_GROUP,
                version=KubernetesClient.get_crd_version(
                    ACTIVE_DIRECTORY_CONNECTOR_CRD_NAME
                ),
                plural=AD_CONNECTOR_RESOURCE_KIND_PLURAL,
            ),
            retry_method="get namespaced custom object",
            retry_on_exceptions=(
                NewConnectionError,
                MaxRetryError,
                KubernetesError,
            ),
        )
        if custom_object_exists:
            raise ValueError(
                "Active Directory connector `{}` already exists in namespace "
                "`{}`.".format(name, namespace)
            )

        spec_object = {
            "apiVersion": AD_CONNECTOR_API_GROUP
            + "/"
            + AD_CONNECTOR_API_VERSION,
            "kind": AD_CONNECTOR_RESOURCE_KIND,
            "metadata": {"name": name},
            "spec": {
                "activeDirectory": {
                    "domainControllers": {
                        "primaryDomainController": primary_domain_controller,
                        "secondaryDomainControllers": secondary_domain_controllers,
                    },
                    "netbiosDomainName": netbios_domain_name,
                    "realm": realm,
                },
                "dns": {
                    "domainName": dns_domain_name,
                    "nameserverIPAddresses": nameserver_addresses,
                    "preferK8sDnsForPtrLookups": prefer_k8s_dns,
                    "replicas": num_dns_replicas,
                },
            },
        }

        cr = CustomResource.decode(
            ActiveDirectoryConnectorCustomResource, spec_object
        )
        cr.metadata.namespace = namespace
        cr.validate(client.apis.kubernetes)

        # Create custom resource
        #
        retry(
            lambda: client.apis.kubernetes.create_namespaced_custom_object(
                cr=cr,
                plural=AD_CONNECTOR_RESOURCE_KIND_PLURAL,
                ignore_conflict=True,
            ),
            retry_method="create namespaced custom object",
            retry_on_exceptions=(
                NewConnectionError,
                MaxRetryError,
                KubernetesError,
            ),
        )

        client.stdout(
            "Deployed Active Directory connect '{0}' in namespace `{1}`.".format(
                name, namespace
            )
        )

    except KubernetesError as e:
        raise ADConnectorError(e.message)
    except Exception as e:
        raise CLIError(e)


# For debugging purposes
def ad_connector_show(
    client,
    name,
    # -- indirect --
    namespace=None,
    use_k8s=None,
    # -- direct --
    data_controller_name=None,
    resource_group=None,
):
    """
    Show the details of an Active Directory connector.
    """
    try:
        if not use_k8s:
            raise ValueError(USE_K8S_EXCEPTION_TEXT)
        else:
            check_and_set_kubectl_context()
            namespace = namespace or client.namespace

            response = _get_ad_connector_custom_resource(
                client, name, namespace
            )

            cr = CustomResource.decode(
                ActiveDirectoryConnectorCustomResource, response
            )
            cr.metadata.namespace = namespace
            cr.validate(client.apis.kubernetes)

            return cr.encode()

    except KubernetesError as e:
        raise ADConnectorError(e.message)
    except Exception as e:
        raise CLIError(e)


def ad_connector_update(
    client,
    name,
    nameserver_addresses=None,
    primary_domain_controller=None,
    secondary_domain_controllers=None,
    num_dns_replicas=None,
    prefer_k8s_dns=None,
    # -- indirect --
    namespace=None,
    use_k8s=None,
    # -- direct --
    data_controller_name=None,
    resource_group=None,
):
    """
    Edit the details of an Active Directory connector.
    """
    try:
        if not use_k8s:
            raise ValueError(USE_K8S_EXCEPTION_TEXT)
        else:
            check_and_set_kubectl_context()
            namespace = namespace or client.namespace

            primary_domain_controller = _parse_primary_domain_controller(
                primary_domain_controller
            )

            secondary_domain_controllers = _parse_secondary_domain_controllers(
                secondary_domain_controllers
            )

            prefer_k8s_dns = _parse_prefer_k8s_dns(prefer_k8s_dns)
            num_dns_replicas = _parse_num_replicas(num_dns_replicas)
            nameserver_addresses = _parse_nameserver_addresses(
                nameserver_addresses
            )

            custom_object_exists = retry(
                lambda: client.apis.kubernetes.namespaced_custom_object_exists(
                    name,
                    namespace,
                    group=AD_CONNECTOR_API_GROUP,
                    version=KubernetesClient.get_crd_version(
                        ACTIVE_DIRECTORY_CONNECTOR_CRD_NAME
                    ),
                    plural=AD_CONNECTOR_RESOURCE_KIND_PLURAL,
                ),
                retry_method="get namespaced custom object",
                retry_on_exceptions=(
                    NewConnectionError,
                    MaxRetryError,
                    KubernetesError,
                ),
            )

            if not custom_object_exists:
                raise ValueError(
                    "Active Directory connector `{}` does not exist in namespace "
                    "`{}`.".format(name, namespace)
                )

            spec_object = {
                "apiVersion": AD_CONNECTOR_API_GROUP
                + "/"
                + AD_CONNECTOR_API_VERSION,
                "kind": AD_CONNECTOR_RESOURCE_KIND,
                "metadata": {"name": name},
                "spec": {
                    "activeDirectory": {
                        "domainControllers": {
                            "primaryDomainController": primary_domain_controller,
                            "secondaryDomainControllers": secondary_domain_controllers,
                        }
                    },
                    "dns": {
                        "nameserverIPAddresses": nameserver_addresses,
                        "preferK8sDnsForPtrLookups": prefer_k8s_dns,
                        "replicas": num_dns_replicas,
                    },
                },
            }

            cr = CustomResource.decode(
                ActiveDirectoryConnectorCustomResource, spec_object
            )
            cr.metadata.namespace = namespace
            cr.validate(client.apis.kubernetes)

            # Patch CR
            client.apis.kubernetes.patch_namespaced_custom_object(
                cr, AD_CONNECTOR_RESOURCE_KIND_PLURAL
            )

            client.stdout(
                "Updated Active Directory connector '{}'".format(name)
            )

    except KubernetesError as e:
        raise ADConnectorError(e.message)
    except Exception as e:
        raise CLIError(e)


def ad_connector_delete(
    client,
    name,
    # -- indirect --
    namespace=None,
    use_k8s=None,
    # -- direct --
    data_controller_name=None,
    resource_group=None,
):
    """
    Delete an Active Directory connector.
    """
    try:
        if not use_k8s:
            raise ValueError(USE_K8S_EXCEPTION_TEXT)

        check_and_set_kubectl_context()
        namespace = namespace or client.namespace

        client.apis.kubernetes.delete_namespaced_custom_object(
            name,
            namespace,
            group=AD_CONNECTOR_API_GROUP,
            version=KubernetesClient.get_crd_version(
                ACTIVE_DIRECTORY_CONNECTOR_CRD_NAME
            ),
            plural=AD_CONNECTOR_RESOURCE_KIND_PLURAL,
        )

        client.stdout(
            "Deleted Active Directory connector '{}' from namespace {}".format(
                name, namespace
            )
        )

    except KubernetesError as e:
        raise ADConnectorError(e.message)
    except Exception as e:
        raise CLIError(e)


def _get_ad_connector_custom_resource(client, name, namespace):
    """
    Queries the kubernetes cluster and returns the custom object for an AD connector with the given name in the specified namespace
    :param client:
    :param name: The name of the AD connector.
    :param namespace: Namespace where the AD connector is deployed.
    :return: The k8s custom resource if one is found. An error will be raised if the AD connector is not found.
    """

    try:
        json_object = client.apis.kubernetes.get_namespaced_custom_object(
            name,
            namespace,
            group=AD_CONNECTOR_API_GROUP,
            version=KubernetesClient.get_crd_version(
                ACTIVE_DIRECTORY_CONNECTOR_CRD_NAME
            ),
            plural=AD_CONNECTOR_RESOURCE_KIND_PLURAL,
        )
        return json_object

    except K8sApiException as e:
        if e.status == http_status_codes.not_found:
            raise ValueError(
                "Active Directory connector `{}` does not exist in namespace `{}`.".format(
                    name, namespace
                )
            )
