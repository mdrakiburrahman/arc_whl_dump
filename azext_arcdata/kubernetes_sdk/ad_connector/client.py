# ------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# ------------------------------------------------------------------------------

"""Command definitions for `data control`."""

from azext_arcdata.ad_connector.util import (
    _get_ad_connector_custom_resource,
    _get_or_create_domain_service_account_secret,
    _parse_num_replicas,
    _parse_prefer_k8s_dns,
    _parse_nameserver_addresses,
    _parse_primary_domain_controller,
    _parse_secondary_domain_controllers,
)
from azext_arcdata.kubernetes_sdk.dc.constants import (
    ACTIVE_DIRECTORY_CONNECTOR_CRD_NAME,
)
from azext_arcdata.core.util import (
    check_and_set_kubectl_context,
    retry,
)
from azext_arcdata.kubernetes_sdk.client import (
    KubernetesClient,
    KubernetesError,
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
from knack.log import get_logger
from urllib3.exceptions import MaxRetryError, NewConnectionError

__all__ = ["ActiveDirectoryConnectorClient"]

logger = get_logger(__name__)


class ActiveDirectoryConnectorClient(object):
    def __init__(self, stdout, stderr):
        check_and_set_kubectl_context()
        self._client = KubernetesClient
        # for now all methods in the KubernetesClient are marked static.  We
        # may need to change them to instance methods going forward.
        self.stdout = stdout
        self.stderr = stderr

    # ------------------------------------------------------------------------ #
    # AD Connector Create
    # ------------------------------------------------------------------------ #

    def create(
        self,
        name,
        namespace,
        realm,
        nameserver_addresses,
        account_provisioning,
        primary_domain_controller=None,
        secondary_domain_controllers=None,
        netbios_domain_name=None,
        dns_domain_name=None,
        num_dns_replicas=1,
        prefer_k8s_dns="true",
        ou_distinguished_name=None,
        domain_service_account_secret=None,
    ):
        client = self._client
        stdout = self.stdout

        nameserver_addresses = _parse_nameserver_addresses(nameserver_addresses)

        primary_domain_controller = _parse_primary_domain_controller(
            primary_domain_controller
        )
        secondary_domain_controllers = _parse_secondary_domain_controllers(
            secondary_domain_controllers
        )
        prefer_k8s_dns = _parse_prefer_k8s_dns(prefer_k8s_dns)
        num_dns_replicas = _parse_num_replicas(num_dns_replicas)

        custom_object_exists = retry(
            lambda: client.namespaced_custom_object_exists(
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

        domain_service_account_secret = (
            _get_or_create_domain_service_account_secret(
                client,
                stdout,
                name,
                namespace,
                account_provisioning,
                domain_service_account_secret,
            )
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
                    "serviceAccountProvisioning": account_provisioning,
                    "ouDistinguishedName": ou_distinguished_name,
                    "domainServiceAccountSecret": domain_service_account_secret,
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
        cr.validate(client)

        # Create custom resource
        #
        retry(
            lambda: client.create_namespaced_custom_object(
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

        stdout(
            "Deployed Active Directory connector '{0}' in namespace `{1}`.".format(
                name, namespace
            )
        )

    # ------------------------------------------------------------------------ #
    # AD Connector Update/Edit
    # ------------------------------------------------------------------------ #

    def update(
        self,
        name,
        namespace,
        nameserver_addresses=None,
        primary_domain_controller=None,
        secondary_domain_controllers=None,
        num_dns_replicas=None,
        prefer_k8s_dns=None,
        domain_service_account_secret=None,
    ):
        client = self._client
        stdout = self.stdout

        primary_domain_controller = _parse_primary_domain_controller(
            primary_domain_controller
        )

        secondary_domain_controllers = _parse_secondary_domain_controllers(
            secondary_domain_controllers
        )

        prefer_k8s_dns = _parse_prefer_k8s_dns(prefer_k8s_dns)
        num_dns_replicas = _parse_num_replicas(num_dns_replicas)
        nameserver_addresses = _parse_nameserver_addresses(nameserver_addresses)

        cr = _get_ad_connector_custom_resource(client, name, namespace)

        if domain_service_account_secret:
            # Get or create a new secret if the user specifies a secret name in update
            #
            account_provisioning = (
                cr.spec.active_directory.service_account_provisioning
            )
            domain_service_account_secret = (
                _get_or_create_domain_service_account_secret(
                    client,
                    name,
                    namespace,
                    account_provisioning,
                    domain_service_account_secret,
                )
            )

        patch_spec_object = {
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
                    "domainServiceAccountSecret": domain_service_account_secret,
                },
                "dns": {
                    "nameserverIPAddresses": nameserver_addresses,
                    "preferK8sDnsForPtrLookups": prefer_k8s_dns,
                    "replicas": num_dns_replicas,
                },
            },
        }

        cr = CustomResource.decode(
            ActiveDirectoryConnectorCustomResource, patch_spec_object
        )
        cr.metadata.namespace = namespace
        cr.validate(client)

        # Patch CR
        client.patch_namespaced_custom_object(
            cr, AD_CONNECTOR_RESOURCE_KIND_PLURAL
        )

        stdout("Updated Active Directory connector '{}'".format(name))

    # ------------------------------------------------------------------------ #
    # AD Connector Show
    # ------------------------------------------------------------------------ #

    def show(self, name, namespace):
        cr = _get_ad_connector_custom_resource(self._client, name, namespace)
        return cr.encode()

    # ------------------------------------------------------------------------ #
    # AD Connector Delete
    # ------------------------------------------------------------------------ #

    def delete(self, name, namespace):
        client = self._client
        stdout = self.stdout

        client.delete_namespaced_custom_object(
            name,
            namespace,
            group=AD_CONNECTOR_API_GROUP,
            version=KubernetesClient.get_crd_version(
                ACTIVE_DIRECTORY_CONNECTOR_CRD_NAME
            ),
            plural=AD_CONNECTOR_RESOURCE_KIND_PLURAL,
        )

        stdout(
            "Deleted Active Directory connector '{}' from namespace {}".format(
                name, namespace
            )
        )
