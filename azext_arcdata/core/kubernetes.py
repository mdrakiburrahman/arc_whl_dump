# ------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# ------------------------------------------------------------------------------

from azext_arcdata.core.http_codes import http_status_codes
from azext_arcdata.core.util import display, retry
from azext_arcdata.core.constants import (
    DOCKER_USERNAME,
    DOCKER_PASSWORD,
    REGISTRY_USERNAME,
    REGISTRY_PASSWORD,
)

from urllib3.exceptions import NewConnectionError, MaxRetryError
from http import HTTPStatus
from kubernetes import client as k8sClient
from kubernetes.client.rest import ApiException as K8sApiException
from knack.log import get_logger

import base64
import json
import os
import re
import yaml


logger = get_logger(__name__)

DEFAULT_DOCKER_IMAGE_PULL_SECRET_NAME = "arc-private-registry"


def validate_namespace(cluster_name):
    """
    Check if the requested namespace is one in which a cluster can
    be deployed into
    """
    namespaces = ["default", "kube-system"]

    if cluster_name.lower() in namespaces:
        raise Exception("Cluster name can not be '%s'." % cluster_name)

    if not re.match(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$", cluster_name):
        raise Exception(
            "Cluster name '"
            + cluster_name
            + "' is invalid. The name must consist of lowercase alphanumeric "
            "characters or '-', and  must start and end with a alphanumeric "
            "character."
        )


def create_namespace(cluster_name, labels=None):
    """
    Create and label the namespace
    """
    # Cluster name has to be DNS compliant by having only lowercase alphanumeric
    # characters or '-', and must start with and end with a alphanumeric
    # character.
    #
    try:
        body = k8sClient.V1Namespace()
        body.metadata = k8sClient.V1ObjectMeta(name=cluster_name, labels=labels)

        k8sClient.CoreV1Api().create_namespace(body=body)
    except K8sApiException as e:
        logger.error(e.body)
        raise


def patch_namespace(cluster_name, body):
    """
    Patch the namespace
    :param cluster_name:
    :param body:
    :return:
    """
    # Cluster name has to be DNS compliant by having only lowercase alphanumeric characters or '-',
    # and must start with and end with a alphanumeric character.
    #
    try:
        k8sClient.CoreV1Api().patch_namespace(name=cluster_name, body=body)
    except K8sApiException as e:
        logger.error(e.body)
        raise


def namespace_is_empty(cluster_name, label=None):
    """
    Returns True if K8s namespace is empty.
    """

    try:
        kwargs = {"label_selector": label} if label else {}

        if (
            len(
                k8sClient.AppsV1Api()
                .list_namespaced_stateful_set(namespace=cluster_name, **kwargs)
                .items
            )
            > 0
        ):
            return False
        elif (
            len(
                k8sClient.AppsV1Api()
                .list_namespaced_daemon_set(namespace=cluster_name, **kwargs)
                .items
            )
            > 0
        ):
            return False
        elif (
            len(
                k8sClient.AppsV1Api()
                .list_namespaced_deployment(namespace=cluster_name, **kwargs)
                .items
            )
            > 0
        ):
            return False
        elif (
            len(
                k8sClient.AppsV1Api()
                .list_namespaced_replica_set(namespace=cluster_name, **kwargs)
                .items
            )
            > 0
        ):
            return False
        elif (
            len(
                k8sClient.CoreV1Api()
                .list_namespaced_service(namespace=cluster_name, **kwargs)
                .items
            )
            > 0
        ):
            return False
        elif (
            len(
                k8sClient.CoreV1Api()
                .list_namespaced_persistent_volume_claim(
                    namespace=cluster_name, **kwargs
                )
                .items
            )
            > 0
        ):
            return False
        elif (
            len(
                k8sClient.CoreV1Api()
                .list_namespaced_pod(namespace=cluster_name, **kwargs)
                .items
            )
            > 0
        ):
            return False
        else:
            return True
    except K8sApiException as e:
        logger.error(e.body)
        return False


def delete_cluster_resources(cluster_name, label=None):
    """
    Delete cluster resources.
    """
    try:
        kwargs = {"label_selector": label} if label else {}
        body = k8sClient.V1DeleteOptions()

        logger.debug("Deleting stateful sets")
        k8sClient.AppsV1Api().delete_collection_namespaced_stateful_set(
            namespace=cluster_name, **kwargs
        )

        logger.debug("Deleting daemon sets")
        k8sClient.AppsV1Api().delete_collection_namespaced_daemon_set(
            namespace=cluster_name, **kwargs
        )

        logger.debug("Deleting deployments")
        k8sClient.AppsV1Api().delete_collection_namespaced_deployment(
            namespace=cluster_name, **kwargs
        )

        logger.debug("Deleting replica sets")
        k8sClient.AppsV1Api().delete_collection_namespaced_replica_set(
            namespace=cluster_name, **kwargs
        )

        logger.debug("Deleting services")
        k8sClient.CoreV1Api().delete_collection_namespaced_service_account(
            namespace=cluster_name, **kwargs
        )
        services = (
            k8sClient.CoreV1Api()
            .list_namespaced_service(namespace=cluster_name, **kwargs)
            .items
        )
        for service in services:
            k8sClient.CoreV1Api().delete_namespaced_service(
                name=service.metadata.name, namespace=cluster_name, body=body
            )

        logger.debug("Deleting secrets")
        k8sClient.CoreV1Api().delete_collection_namespaced_secret(
            namespace=cluster_name, **kwargs
        )

        secrets = (
            k8sClient.CoreV1Api()
            .list_namespaced_secret(namespace=cluster_name)
            .items
        )
        controller_token_secret = "controller-token-secret"
        names = [n.metadata.name for n in secrets]
        if names and controller_token_secret in names:
            k8sClient.CoreV1Api().delete_namespaced_secret(
                name=controller_token_secret, namespace=cluster_name, body=body
            )

        controller_token_private_secret = "controller-token-private-secret"
        if names and controller_token_private_secret in names:
            k8sClient.CoreV1Api().delete_namespaced_secret(
                name=controller_token_private_secret,
                namespace=cluster_name,
                body=body,
            )

        app_service_proxy = "appproxy-secret"
        if names and app_service_proxy in names:
            k8sClient.CoreV1Api().delete_namespaced_secret(
                name=app_service_proxy, namespace=cluster_name, body=body
            )

        logger.debug("Deleting persistent volume claims")
        k8sClient.CoreV1Api().delete_collection_namespaced_persistent_volume_claim(
            namespace=cluster_name, **kwargs
        )

        logger.debug("Deleting Controller replica set")
        controller_replicaset = "control"
        replicasets = (
            k8sClient.AppsV1Api()
            .list_namespaced_replica_set(namespace=cluster_name)
            .items
        )
        names = [n.metadata.name for n in replicasets]
        if names and controller_replicaset in names:
            k8sClient.AppsV1Api().delete_namespaced_replica_set(
                name=controller_replicaset, namespace=cluster_name, body=body
            )

        logger.debug("Deleting pods")
        k8sClient.CoreV1Api().delete_collection_namespaced_pod(
            namespace=cluster_name, **kwargs
        )

        logger.debug("Deleting service accounts")
        k8sClient.CoreV1Api().delete_collection_namespaced_service_account(
            namespace=cluster_name, **kwargs
        )

        logger.debug("Deleting roles")
        k8sClient.RbacAuthorizationV1Api().delete_collection_namespaced_role_binding(
            namespace=cluster_name, **kwargs
        )
        k8sClient.RbacAuthorizationV1Api().delete_collection_namespaced_role(
            namespace=cluster_name, **kwargs
        )

        admin_rule = "namespaced-admin"
        roles = (
            k8sClient.RbacAuthorizationV1Api()
            .list_namespaced_role(namespace=cluster_name)
            .items
        )
        names = [n.metadata.name for n in roles]
        if names and admin_rule in names:
            k8sClient.RbacAuthorizationV1Api().delete_namespaced_role(
                name=admin_rule, namespace=cluster_name, body=body
            )

        logger.debug("Deleting config maps")
        k8sClient.CoreV1Api().delete_collection_namespaced_config_map(
            namespace=cluster_name, **kwargs
        )

        return (namespace_is_empty(cluster_name, label=label), HTTPStatus.OK)

    except K8sApiException as e:
        # If a 403 Forbidden is returned by K8s
        #
        if e.status == HTTPStatus.FORBIDDEN:
            display(
                "Failed to delete the cluster resources using Kubernetes API. "
                "Ensure that the delete permissions are set for the current "
                "kubectl context."
            )
            logger.debug(e)
            # return True to avoid retries for a 403 error
            #
            return True, HTTPStatus.FORBIDDEN
        return False, e.status


def get_namespace(cluster_name):
    """
    Get k8s namespace.
    :param cluster_name: name of the cluster namespace
    :return:
    """
    try:
        ns = k8sClient.CoreV1Api().read_namespace(cluster_name)
        return ns
    except K8sApiException as e:
        logger.debug(e.body)
        raise


def namespace_exists(cluster_name):
    """
    Return true if K8s namespace exists.
    """
    try:
        ns = get_namespace(cluster_name)
        return ns and cluster_name == ns.metadata.name
    except K8sApiException as e:
        logger.debug(e.body)
        return False


def update_namespace_label(cluster_name):
    """
    Update K8s namespace label and add the MSSQL_CLUSTER if not already added.
    """
    try:
        namespaces_list = k8sClient.CoreV1Api().list_namespace().items
        for namespace in namespaces_list:

            # Find the namespace
            #
            if namespace.metadata.name == cluster_name:
                # Add MSSQL_CLUSTER label to existing labels
                #
                labels = namespace.metadata.labels or {}
                labels["MSSQL_CLUSTER"] = cluster_name
                body = k8sClient.V1Namespace()
                body.metadata = k8sClient.V1ObjectMeta(labels=labels)
                k8sClient.CoreV1Api().patch_namespace(
                    name=cluster_name, body=body
                )
                return
    except K8sApiException as e:
        logger.error(e.body)
        raise


def delete_namespace(cluster_name):
    """
    Delete K8s namespace.
    """
    try:
        namespacesList = (
            k8sClient.CoreV1Api()
            .list_namespace(label_selector="MSSQL_CLUSTER=" + cluster_name)
            .items
        )
        namespaces = [n.metadata.name for n in namespacesList]
        if cluster_name in namespaces:
            k8sClient.CoreV1Api().delete_namespace(
                name=cluster_name, body=k8sClient.V1DeleteOptions()
            )
            display("Cluster deleted.")
        else:
            display("Cluster does not exist or is not a SQL cluster.")
    except K8sApiException as e:
        logger.error(e.body)
        raise


def setup_private_registry(
    cluster_name,
    docker_registry,
    secret_name=DEFAULT_DOCKER_IMAGE_PULL_SECRET_NAME,
    ignore_conflict=False,
):
    """
    Setup private docker repository secret.
    """
    try:
        body = create_registry_secret(
            cluster_name, docker_registry, secret_name=secret_name
        )

        k8sClient.CoreV1Api().create_namespaced_secret(
            namespace=cluster_name, body=body
        )
    except K8sApiException as e:
        if not (ignore_conflict and e.status == http_status_codes.conflict):
            raise


def update_private_registry(
    cluster_name,
    docker_registry,
    secret_name=DEFAULT_DOCKER_IMAGE_PULL_SECRET_NAME,
):
    """
    Update private docker repository secret.
    """
    try:
        body = create_registry_secret(
            cluster_name, docker_registry, secret_name=secret_name
        )

        k8sClient.CoreV1Api().patch_namespaced_secret(
            name=secret_name, namespace=cluster_name, body=body
        )
    except K8sApiException as e:
        if e.status == HTTPStatus.NOT_FOUND:
            try:
                k8sClient.CoreV1Api().create_namespaced_secret(
                    namespace=cluster_name, body=body
                )
            except K8sApiException as e:
                logger.error(e.body)
                raise
        else:
            logger.error(e.body)
            raise


def create_registry_secret(
    cluster_name,
    docker_registry,
    secret_name=DEFAULT_DOCKER_IMAGE_PULL_SECRET_NAME,
):
    """
    Create the private docker repository secret.
    """
    # .dockerconfigjson field is a base64 encoded string of the private
    #  registry credentials, which has the following format :
    # {
    #    "auths":{
    #       "docker_server":{
    #          "username":"<username>",
    #          "password":"<password>",
    #          "email":"<email>",
    #          "auth":"<username>:<password>"
    #       }
    #    }
    # }
    #

    un = os.getenv(REGISTRY_USERNAME)
    pw = os.getenv(REGISTRY_PASSWORD)

    # Fallback to old environment variables.
    if not un:
        un = os.getenv(DOCKER_USERNAME)
    if not pw:
        pw = os.getenv(DOCKER_PASSWORD)

    b64_auth = base64.b64encode((un + ":" + pw).encode("utf-8")).decode("utf-8")

    credentials = dict()
    credentials["username"] = un
    credentials["password"] = pw
    credentials["email"] = un
    credentials["auth"] = b64_auth
    credentials_registry_server = dict()
    credentials_registry_server[docker_registry] = credentials
    auths_dict = dict()
    auths_dict["auths"] = credentials_registry_server
    docker_config_json = json.dumps(auths_dict)
    b64_docker_config_json = base64.b64encode(
        docker_config_json.encode("utf-8")
    ).decode("utf-8")

    body = k8sClient.V1Secret()
    body.type = "kubernetes.io/dockerconfigjson"
    body.data = {".dockerconfigjson": b64_docker_config_json}
    body.kind = "Secret"
    body.metadata = k8sClient.V1ObjectMeta(
        name=secret_name,
        namespace=cluster_name,
        labels={"MSSQL_CLUSTER": cluster_name},
    )

    return body


def create_empty_secret(cluster_name, secret_name):
    """
    Creates an empty secret in Kubernetes
    """
    try:
        body = k8sClient.V1Secret()
        body.type = "Opaque"
        body.kind = "Secret"
        body.metadata = k8sClient.V1ObjectMeta(
            name=secret_name,
            namespace=cluster_name,
            labels={"MSSQL_CLUSTER": cluster_name},
        )
        k8sClient.CoreV1Api().create_namespaced_secret(
            namespace=cluster_name, body=body
        )
    except K8sApiException as e:
        logger.error(e.body)
        raise


def update_cluster_role(cluster_role_name, cluster_role_body):
    """
    Update the cluster role.
    """
    try:
        k8sClient.RbacAuthorizationV1Api().patch_cluster_role(
            name=cluster_role_name, body=cluster_role_body
        )
    except K8sApiException as e:
        if e.status == HTTPStatus.NOT_FOUND:
            try:
                k8sClient.RbacAuthorizationV1Api().create_cluster_role(
                    body=cluster_role_body
                )
            except K8sApiException as e:
                raise
        else:
            raise


def update_cluster_role_binding(
    cluster_role_binding_name, cluster_role_binding_body
):
    """
    Update the cluster role binding.
    """
    try:
        k8sClient.RbacAuthorizationV1Api().patch_cluster_role_binding(
            name=cluster_role_binding_name, body=cluster_role_binding_body
        )
    except K8sApiException as e:
        if e.status == HTTPStatus.NOT_FOUND:
            try:
                k8sClient.RbacAuthorizationV1Api().create_cluster_role_binding(
                    body=cluster_role_binding_body
                )
            except K8sApiException as e:
                raise
        else:
            raise


def create_config_map(cluster_name, config_map_name, data):
    """
    Creates an empty config map in Kubernetes
    """
    try:
        body = k8sClient.V1ConfigMap(data=data)
        body.kind = "ConfigMap"
        body.metadata = k8sClient.V1ObjectMeta(
            name=config_map_name,
            namespace=cluster_name,
            labels={"MSSQL_CLUSTER": cluster_name},
        )
        k8sClient.CoreV1Api().create_namespaced_config_map(
            namespace=cluster_name, body=body
        )
    except K8sApiException as e:
        logger.error(e.body)
        raise


def get_config_map(cluster_name, config_map_name):
    """
    Retrieve the requested config map
    """
    try:
        config_map = k8sClient.CoreV1Api().read_namespaced_config_map(
            config_map_name, cluster_name
        )

        return config_map

    except k8sClient.rest.ApiException as e:
        logger.error(e.body)
        raise


def patch_config_map(cluster_name, config_map_name, patch):
    """
    Patch the config map
    """
    try:
        k8sClient.CoreV1Api().patch_namespaced_config_map(
            config_map_name, cluster_name, patch
        )
    except K8sApiException as e:
        logger.error(e.body)
        raise


def create_secret(cluster_name, config):
    """
    Creates a secret in Kubernetes
    """

    try:
        body = yaml.safe_load(config)
        k8sClient.CoreV1Api().create_namespaced_secret(
            namespace=cluster_name, body=body
        )
    except K8sApiException as e:
        logger.error(e.body)
        raise


def service_account_exists(cluster_name, service_account_name):
    """
    Returns true if service account exists in the namespace
    """

    try:
        service_account = k8sClient.CoreV1Api().read_namespaced_service_account(
            service_account_name, cluster_name
        )
        return service_account_name == service_account.metadata.name
    except K8sApiException as e:
        logger.debug(e.body)
        return False


def namespaced_role_exists(cluster_name, role_name):
    """
    Returns true if role exists in the namespace
    """

    try:
        role = k8sClient.RbacAuthorizationV1Api().read_namespaced_role(
            role_name, cluster_name
        )
        return role_name == role.metadata.name
    except K8sApiException as e:
        logger.debug(e.body)
        return False


def namespaced_role_binding_exists(cluster_name, role_binding_name):
    """
    Returns true if role binding exists in the namespace
    """

    try:
        role_binding = (
            k8sClient.RbacAuthorizationV1Api().read_namespaced_role_binding(
                role_binding_name, cluster_name
            )
        )
        return role_binding_name == role_binding.metadata.name
    except K8sApiException as e:
        logger.debug(e.body)
        return False


def cluster_role_exists(role_name):
    """
    Returns true if cluster role exists
    """

    try:
        role = k8sClient.RbacAuthorizationV1Api().read_cluster_role(role_name)
        return role_name == role.metadata.name
    except K8sApiException as e:
        logger.debug(e.body)
        return False


def cluster_role_binding_exists(role_binding_name):
    """
    Returns true if cluster role binding exists
    """

    try:
        role_binding = (
            k8sClient.RbacAuthorizationV1Api().read_cluster_role_binding(
                role_binding_name
            )
        )
        return role_binding_name == role_binding.metadata.name
    except K8sApiException as e:
        logger.debug(e.body)
        return False


def is_instance_ready(cr):
    """
    Verify that the custom resource instance is ready
    :param cr: Instance to check the readiness of
    :return: True if the instance is ready, False otherwise
    """
    return cr.metadata.generation == cr.status.observed_generation and (
        cr.status.state is not None and cr.status.state.lower() == "ready"
    )


def create_namespace_with_retry(namespace: str, cluster_label_key: str = None, annotations: dict = None):
    """
    Create kubernetes namespace
    """

    CONNECTION_RETRY_ATTEMPTS = 12
    RETRY_INTERVAL = 5

    validate_namespace(namespace)

    # Create namespace if it doesn't already exit
    #
    if not retry(
        namespace_exists,
        namespace,
        retry_count=CONNECTION_RETRY_ATTEMPTS,
        retry_delay=RETRY_INTERVAL,
        retry_method="check if namespace exists",
        retry_on_exceptions=(NewConnectionError, MaxRetryError),
    ):
        labels = {cluster_label_key: namespace} if cluster_label_key else None

        retry(
            create_namespace,
            namespace,
            labels,
            retry_count=CONNECTION_RETRY_ATTEMPTS,
            retry_delay=RETRY_INTERVAL,
            retry_method="create namespace",
            retry_on_exceptions=(NewConnectionError, MaxRetryError),
        )

    # Populate namespace required annotations
    #
    if retry(
        namespace_is_empty,
        namespace,
        retry_count=CONNECTION_RETRY_ATTEMPTS,
        retry_delay=RETRY_INTERVAL,
        retry_method="check if namespace is empty",
        retry_on_exceptions=(NewConnectionError, MaxRetryError),
    ):
        namespace_response = k8sClient.CoreV1Api().read_namespace(
            namespace
        )

        if cluster_label_key:
            if (
                namespace_response.metadata.labels is None
                or cluster_label_key
                not in namespace_response.metadata.labels
            ):
                display(
                    'NOTE: Namespace "%s" is already created and will '
                    'not be labeled with "%s" Kubernetes label.'
                    % (namespace, cluster_label_key)
                )
                display(
                    "This is an informational message only, no user "
                    "action is required."
                )
                display("")

        if annotations:
            body = k8sClient.V1Namespace()
            body.metadata = k8sClient.V1ObjectMeta(annotations=annotations)

            retry(
                lambda: patch_namespace(namespace, body),
                retry_count=CONNECTION_RETRY_ATTEMPTS,
                retry_delay=RETRY_INTERVAL,
                retry_method="patch namespace",
                retry_on_exceptions=(NewConnectionError, MaxRetryError),
            )
    else:
        raise Exception(
            "Cluster creation not initiated because the existing "
            "namespace %s "
            'is not empty. Run "kubectl get all -n %s "'
            " to see the existing objects in the namespace"
            % (namespace, namespace)
        )
