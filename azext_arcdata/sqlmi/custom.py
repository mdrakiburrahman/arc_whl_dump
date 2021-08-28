# ------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# ------------------------------------------------------------------------------
import azext_arcdata.core.kubernetes as kubernetes_util
from azext_arcdata.kubernetes_sdk.client import (
    KubernetesError,
    K8sApiException,
    http_status_codes,
)
from azext_arcdata.kubernetes_sdk.models.custom_resource import CustomResource
from azext_arcdata.kubernetes_sdk.models.data_controller_custom_resource import (
    DataControllerCustomResource,
)
from azext_arcdata.core.prompt import prompt, prompt_pass
from azext_arcdata.core.labels import parse_labels
from azext_arcdata.core.util import (
    FileUtil,
    is_windows,
    retry,
    check_and_set_kubectl_context,
    get_config_from_template,
)
from azext_arcdata.core.constants import (
    AZDATA_USERNAME,
    AZDATA_PASSWORD,
    ARC_GROUP,
    DATA_CONTROLLER_CRD_VERSION,
    DATA_CONTROLLER_PLURAL,
    USE_K8S_EXCEPTION_TEXT,
)
from azext_arcdata.sqlmi.exceptions import SqlmiError
from azext_arcdata.sqlmi.models.sqlmi_cr_model import SqlmiCustomResource
from azext_arcdata.sqlmi.models.dag_cr import DagCustomResource

from azext_arcdata.sqlmi.util import (
    is_valid_sql_password,
    is_valid_connectivity_mode,
    validate_labels_and_annotations,
    hierarchical_output,
    parse_cert_files,
    validate_certificate_secret,
    validate_admin_login_secret,
    create_certificate_secret,
    check_secret_exists_with_retries,
    CONNECTION_RETRY_ATTEMPTS,
    RETRY_INTERVAL,
)
from azext_arcdata.sqlmi.constants import (
    RESOURCE_KIND,
    RESOURCE_KIND_PLURAL,
    API_GROUP,
    API_VERSION,
    SQLMI_LICENSE_TYPE_DEFAULT,
    SQLMI_TIER_GENERAL_PURPOSE_SHORT,
    SQLMI_TIER_GENERAL_PURPOSE,
    SQLMI_TIER_BUSINESS_CRITICAL_SHORT,
    SQLMI_TIER_BUSINESS_CRITICAL,
    SQLMI_TIER_DEFAULT,
    DAG_RESOURCE_KIND,
    DAG_RESOURCE_KIND_PLURAL,
    DAG_API_GROUP,
    DAG_API_VERSION,
    SQLMI_SPEC,
)

from azext_arcdata.dc.constants import (
    POSTGRES_CRD,
    SQLMI_CRD,
    SQLMI_RESTORE_TASK_CRD,
    EXPORT_TASK_CRD,
    DAG_CRD,
    MONITOR_CRD,
    DATA_CONTROLLER_CRD,
)

from knack.cli import CLIError
from knack.log import get_logger
from humanfriendly.terminal.spinners import AutomaticSpinner
from urllib3.exceptions import NewConnectionError, MaxRetryError
from datetime import datetime

import json
import os
import base64
import yaml
import sys
import time
import shutil

logger = get_logger(__name__)


def arc_sql_mi_create(
    client,
    name,
    namespace,
    path=None,
    replicas=None,
    cores_limit=None,
    cores_request=None,
    memory_limit=None,
    memory_request=None,
    storage_class_data=None,
    storage_class_logs=None,
    storage_class_datalogs=None,
    storage_class_backups=None,
    volume_size_data=None,
    volume_size_logs=None,
    volume_size_datalogs=None,
    volume_size_backups=None,
    nowait=False,
    noexternal_endpoint=None,
    certificate_public_key_file=None,
    certificate_private_key_file=None,
    service_certificate_secret=None,
    admin_login_secret=None,
    license_type=None,
    tier=None,
    dev=None,
    labels=None,
    annotations=None,
    service_labels=None,
    service_annotations=None,
    storage_labels=None,
    storage_annotations=None,
    use_k8s=None,
    collation=None,
    language=None,
    agent_enabled=None,
    trace_flags=None,
    time_zone=None,
):
    """
    Create a SQL managed instance.
    """

    args = locals()

    try:

        if not use_k8s:
            raise ValueError(USE_K8S_EXCEPTION_TEXT)

        check_and_set_kubectl_context()
        namespace = client.namespace

        # Determine source for the resource spec preferring path first
        #
        if not path:
            # TODO: Use mutating web hooks to set these default values
            #
            spec_object = {
                "apiVersion": API_GROUP + "/" + API_VERSION,
                "kind": RESOURCE_KIND,
                "metadata": {},
                "spec": {
                    "backup": {"recoveryPointObjectiveInSeconds": 300},
                    "tier": SQLMI_TIER_DEFAULT,
                    "licenseType": SQLMI_LICENSE_TYPE_DEFAULT,
                    "storage": {
                        "data": {"volumes": [{"size": "5Gi"}]},
                        "logs": {"volumes": [{"size": "5Gi"}]},
                    },
                },
            }

        # Otherwise, use the provided azext_arcdata file.
        #
        else:
            spec_object = FileUtil.read_json(path)

        # Decode base spec and apply args. Must patch namespace in separately
        # since it's not parameterized in this func
        cr = CustomResource.decode(SqlmiCustomResource, spec_object)
        cr.metadata.namespace = namespace
        cr.apply_args(**args)
        cr.validate(client.apis.kubernetes)

        # If tier is provided and not replicas, then default replicas based on given tier value
        #
        if tier:
            if not replicas:
                if (tier == SQLMI_TIER_BUSINESS_CRITICAL) or (
                    tier == SQLMI_TIER_BUSINESS_CRITICAL_SHORT
                ):
                    cr.spec.replicas = 3

        if replicas:
            try:
                cr.spec.replicas = int(replicas)

                # Set the tier based on specfied replicas. With fail safe validation enabled, it will go in error
                # if user specifies incorrect value.
                #
                if not tier:
                    if cr.spec.replicas == 1:
                        cr.spec.tier = SQLMI_TIER_GENERAL_PURPOSE
                    else:
                        cr.spec.tier = SQLMI_TIER_BUSINESS_CRITICAL
            except ValueError as e:
                raise CLIError(e)

        validate_labels_and_annotations(
            labels,
            annotations,
            service_labels,
            service_annotations,
            storage_labels,
            storage_annotations,
        )

        custom_object_exists = retry(
            lambda: client.apis.kubernetes.namespaced_custom_object_exists(
                name,
                namespace,
                group=API_GROUP,
                version=API_VERSION,
                plural=RESOURCE_KIND_PLURAL,
            ),
            retry_count=CONNECTION_RETRY_ATTEMPTS,
            retry_delay=RETRY_INTERVAL,
            retry_method="get namespaced custom object",
            retry_on_exceptions=(
                NewConnectionError,
                MaxRetryError,
                KubernetesError,
            ),
        )
        if custom_object_exists:
            raise ValueError(
                "Arc SQL managed instance `{}` already exists in namespace "
                "`{}`.".format(name, namespace)
            )

        if not noexternal_endpoint:
            response = retry(
                lambda: client.apis.kubernetes.list_namespaced_custom_object(
                    namespace,
                    group=ARC_GROUP,
                    version=DATA_CONTROLLER_CRD_VERSION,
                    plural=DATA_CONTROLLER_PLURAL,
                ),
                retry_count=CONNECTION_RETRY_ATTEMPTS,
                retry_delay=RETRY_INTERVAL,
                retry_method="list namespaced custom object",
                retry_on_exceptions=(
                    NewConnectionError,
                    MaxRetryError,
                    K8sApiException,
                ),
            )

            dcs = response.get("items")
            if not dcs:
                raise CLIError(
                    "No data controller exists in namespace `{}`. Cannot set "
                    "external endpoint argument.".format(namespace)
                )
            else:
                is_valid_connectivity_mode(client)
                dc_cr = CustomResource.decode(
                    DataControllerCustomResource, dcs[0]
                )
                cr.spec.services.primary.serviceType = (
                    dc_cr.get_controller_service().serviceType
                )

        # Create admin login secret
        #
        if not admin_login_secret:
            # Use default secret name when the user does not provide one.
            #
            admin_login_secret = name + "-login-secret"

        # Stamp the secret name on the custom resource.
        #
        cr.spec.security.adminLoginSecret = admin_login_secret

        login_secret_exists = check_secret_exists_with_retries(
            client, cr.metadata.namespace, admin_login_secret
        )

        if login_secret_exists:
            # Validate that the existing login secret has correct format.
            #
            validate_admin_login_secret(
                client, cr.metadata.namespace, admin_login_secret
            )
        else:
            # Username
            #
            username = os.environ.get(AZDATA_USERNAME)
            if not username:
                if sys.stdin.isatty():
                    username = prompt("Arc SQL managed instance username:")
                else:
                    raise ValueError(
                        "Please provide an Arc SQL managed instance password "
                        "through the env variable AZDATA_USERNAME."
                    )
            else:
                client.stdout(
                    "Using AZDATA_USERNAME environment variable for `{}` "
                    "username.".format(name)
                )

            while username == "sa" or username == "":
                if username == "sa":
                    username = prompt(
                        "The login 'sa' is not allowed.  Please use a "
                        "different login."
                    )
                if username == "":
                    username = prompt(
                        "Login username required. Please enter a login."
                    )

            # Password
            pw = os.environ.get(AZDATA_PASSWORD)
            if not pw:
                if sys.stdin.isatty():
                    while not pw:
                        pw = prompt_pass(
                            "Arc SQL managed instance password:", True
                        )
                        if not is_valid_sql_password(pw, "sa"):
                            client.stderr(
                                "\nError: SQL Server passwords must be at "
                                "least 8 characters long, cannot contain the "
                                "username, and must contain characters from "
                                "three of the following four sets: Uppercase "
                                "letters, Lowercase letters, Base 10 digits, "
                                "and Symbols. Please try again.\n"
                            )
                            pw = None
                else:
                    raise ValueError(
                        "Please provide an Arc SQL managed instance password "
                        "through the env variable AZDATA_PASSWORD."
                    )
            else:
                client.stdout(
                    "Using AZDATA_PASSWORD environment variable for `{}` "
                    "password.".format(name)
                )

            secrets = dict()
            encoding = "utf-8"
            secrets["secretName"] = admin_login_secret
            secrets["base64Username"] = base64.b64encode(
                bytes(username, encoding)
            ).decode(encoding)
            secrets["base64Password"] = base64.b64encode(
                bytes(pw, encoding)
            ).decode(encoding)
            temp = get_config_from_template(
                os.path.join(
                    os.path.dirname(os.path.realpath(__file__)),
                    "templates",
                    "useradmin-login.yaml.tmpl",
                ),
                secrets,
            )
            mssql_secret = yaml.safe_load(temp)

            try:
                retry(
                    lambda: client.apis.kubernetes.create_secret(
                        cr.metadata.namespace,
                        mssql_secret,
                        ignore_conflict=True,
                    ),
                    retry_count=CONNECTION_RETRY_ATTEMPTS,
                    retry_delay=RETRY_INTERVAL,
                    retry_method="create secret",
                    retry_on_exceptions=(
                        NewConnectionError,
                        MaxRetryError,
                        K8sApiException,
                    ),
                )

            except K8sApiException as e:
                if e.status != http_status_codes.conflict:
                    raise

        # Handle certificate secret related parameters.
        #
        # Cases:
        #
        # 1. When only one of certificate_public_key_file and certificate_private_key_file
        #    are provided, fail with a message saying both are required if one is provided.
        #
        # 2. When both certificate_public_key_file and certificate_private_key_file are
        #    provided, then there are two subcases:
        #
        #    2.1. If service_certificate_secret parameter is NOT provided, use default name
        #         for the secret along with a unique id such as timestamp appended to it.
        #         Check if the secret exists.
        #
        #         2.1.1. If secret does not exist, then create it.
        #
        #         2.1.2. If the secret exists, retry with a different unique identifier.
        #
        #    2.2. If service_certificate_secret parameter is provided, use that string as
        #         the secret name and check if the secret exists.
        #
        #         2.2.1. If secret does not exist, then create it.
        #
        #         2.2.2. If the secret exists, fail indicating that if the secret exists and
        #                the parameters for certificate files should not be provided.
        #
        # 3. When both certificate_public_key_file and certificate_private_key_file are NOT
        #    provided, then there are two subcases:
        #
        #    3.1. If service_certificate_secret parameter is NOT provided, do NOT use default
        #         value. User intends to use system generated certificate.
        #
        #    3.2. If service_certificate_secret parameter is provided, use that string as
        #         the secret name and check if the secret already exists.
        #
        #         3.2.1. If the secret exists, validate and use it.
        #
        #         3.2.2. If the secret does not exist, fail.

        create_new_secret = False
        use_existing_secret = False
        default_service_certificate_secret_name = name + "-certificate-secret"

        # Erase the certificate name from the custom resource.
        # It will be added only if necessary upon validation.
        #
        cr.spec.security.serviceCertificateSecret = ""

        # Case 1. When only one of certificate_public_key_file and certificate_private_key_file
        #         are provided, fail with a message saying both are required if one is provided.
        #
        if not certificate_public_key_file and certificate_private_key_file:
            raise ValueError(
                "Certificate public key file path must be provided "
                "when private key path is provided."
            )

        if certificate_public_key_file and not certificate_private_key_file:
            raise ValueError(
                "Certificate private key file path must be provided "
                "when public key path is provided."
            )

        # Case 2. When both certificate_public_key_file and certificate_private_key_file are
        #         provided.
        #
        if certificate_public_key_file and certificate_private_key_file:

            # Case 2.1. If service_certificate_secret parameter is NOT provided, use default name
            #           for the secret along with a unique id such as timestamp appended to it.
            #           Check if the secret exists.
            #
            if not service_certificate_secret:

                # Case 2.1.1. If secret does not exist, then create it.
                #
                # Case 2.1.2. If the secret exists, retry with a different unique identifier.
                #
                certificate_secret_exists = True
                while certificate_secret_exists:
                    timestamp = datetime.now().strftime(
                        "%m-%d-%Y-%H-%M-%S-%f"
                    )  # e.g. '07-02-2021-23-00-37-846604'

                    # Secret name must be a valid DNS-1123 subdomain name.
                    # Kubernetes uses this regex for validation:
                    # '[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*'
                    #
                    service_certificate_secret = (
                        default_service_certificate_secret_name
                        + "-"
                        + timestamp
                    )

                    certificate_secret_exists = (
                        check_secret_exists_with_retries(
                            client,
                            cr.metadata.namespace,
                            service_certificate_secret,
                        )
                    )

                # Set flag to create new secret.
                #
                create_new_secret = True

            # Case 2.2. If service_certificate_secret parameter is provided, use that string as
            #           the secret name and check if the secret exists.
            #
            else:
                certificate_secret_exists = check_secret_exists_with_retries(
                    client, cr.metadata.namespace, service_certificate_secret
                )

                # Case 2.2.1. If secret does not exist, then create it.
                #
                if not certificate_secret_exists:

                    # Set flag to create new secret.
                    #
                    create_new_secret = True

                # Case 2.2.2. If the secret exists, fail indicating that if the secret exists and
                #             the parameters for certificate files should not be provided.
                #
                else:
                    raise ValueError(
                        "Kubernetes secret '"
                        + service_certificate_secret
                        + "' already exists while private key and public key files "
                        + "are provided on the command line. If you intend to use "
                        "the secret, please remove the file parameters and try again. "
                        "If you intend to use the files provided to the command, "
                        "use a different secret name or delete the existing secret."
                    )

        # Case 3. When both certificate_public_key_file and certificate_private_key_file are
        #         NOT provided.
        #
        if not certificate_public_key_file and not certificate_private_key_file:

            # Case 3.1. If service_certificate_secret parameter is NOT provided, do NOT use default
            #           value. User intends to use system generated certificate.
            #
            if not service_certificate_secret:
                pass

            # Case 3.2. If service_certificate_secret parameter is provided, use that string as
            #           the secret name and check if the secret already exists.
            #
            else:
                certificate_secret_exists = check_secret_exists_with_retries(
                    client, cr.metadata.namespace, service_certificate_secret
                )

                # Case 3.2.1. If the secret exists, validate and use it.
                #
                if certificate_secret_exists:

                    # Set flag to use existing secret.
                    #
                    use_existing_secret = True

                # Case 3.2.2. If the secret does not exist, fail.
                #
                else:
                    raise ValueError(
                        "Kubernetes secret '"
                        + service_certificate_secret
                        + "' does not exist. If you intend to use a pre-existing "
                        "secret, please provide correct name of an existing secret. "
                        "If you intend to use a certificate from public key and "
                        "private key files, please provide their paths in the "
                        "parameters --cert-public-key-file and --cert-private-key-file."
                    )

        # If we decided to create a new secret, create it here.
        #
        if create_new_secret:

            # Validate and parse data from files.
            #
            public_key, private_key = parse_cert_files(
                certificate_public_key_file, certificate_private_key_file
            )

            # Create secret.
            #
            create_certificate_secret(
                client,
                cr.metadata.namespace,
                service_certificate_secret,
                public_key,
                private_key,
            )

            # Set the secret name on custom resource spec to indicate to the operator that we
            # will use certificate from the Kubernetes secret.
            #
            cr.spec.security.serviceCertificateSecret = (
                service_certificate_secret
            )

        # If we decided to use an existing secret, validate it and pass on.
        #
        elif use_existing_secret:

            # Load secret and validate contents.
            #
            validate_certificate_secret(
                client, cr.metadata.namespace, service_certificate_secret
            )

            # Set the secret name on the custom resource spec to indicate to the operator that a
            # user provided certificate is available to use.
            #
            cr.spec.security.serviceCertificateSecret = (
                service_certificate_secret
            )

        # Create custom resource.
        #
        retry(
            lambda: client.apis.kubernetes.create_namespaced_custom_object(
                cr=cr, plural=RESOURCE_KIND_PLURAL, ignore_conflict=True
            ),
            retry_count=CONNECTION_RETRY_ATTEMPTS,
            retry_delay=RETRY_INTERVAL,
            retry_method="create namespaced custom object",
            retry_on_exceptions=(
                NewConnectionError,
                MaxRetryError,
                KubernetesError,
            ),
        )

        if nowait:
            client.stdout(
                "Deployed {0} in namespace `{1}`. Please use `az sql mi-arc "
                "show -n {0} --k8s-namespace {1} --use-k8s` to check its status.".format(
                    cr.metadata.name, cr.metadata.namespace
                )
            )
        else:
            response = retry(
                lambda: client.apis.kubernetes.get_namespaced_custom_object(
                    cr.metadata.name,
                    cr.metadata.namespace,
                    group=API_GROUP,
                    version=API_VERSION,
                    plural=RESOURCE_KIND_PLURAL,
                ),
                retry_count=CONNECTION_RETRY_ATTEMPTS,
                retry_delay=RETRY_INTERVAL,
                retry_method="get namespaced custom object",
                retry_on_exceptions=(
                    NewConnectionError,
                    MaxRetryError,
                    KubernetesError,
                ),
            )
            deployed_cr = CustomResource.decode(SqlmiCustomResource, response)

            if not is_windows():
                with AutomaticSpinner(
                    "Deploying {0} in namespace `{1}`".format(
                        cr.metadata.name, cr.metadata.namespace
                    ),
                    show_time=True,
                ):
                    while not _is_instance_ready(deployed_cr):
                        if _is_instance_in_error(deployed_cr):
                            client.stdout(
                                "{0} is in error state: {1}".format(
                                    cr.metadata.name,
                                    _get_error_message(deployed_cr),
                                )
                            )
                            break

                        time.sleep(5)
                        response = retry(
                            lambda: client.apis.kubernetes.get_namespaced_custom_object(
                                cr.metadata.name,
                                cr.metadata.namespace,
                                group=API_GROUP,
                                version=API_VERSION,
                                plural=RESOURCE_KIND_PLURAL,
                            ),
                            retry_count=CONNECTION_RETRY_ATTEMPTS,
                            retry_delay=RETRY_INTERVAL,
                            retry_method="get namespaced custom object",
                            retry_on_exceptions=(
                                NewConnectionError,
                                MaxRetryError,
                                KubernetesError,
                            ),
                        )

                        deployed_cr = CustomResource.decode(
                            SqlmiCustomResource, response
                        )
            else:
                client.stdout(
                    "Deploying {0} in namespace `{1}`".format(name, namespace)
                )
                while not _is_instance_ready(deployed_cr):
                    if _is_instance_in_error(deployed_cr):
                        client.stdout(
                            "{0} is in error state: {1}".format(
                                cr.metadata.name,
                                _get_error_message(deployed_cr),
                            )
                        )
                        break

                    time.sleep(5)
                    response = retry(
                        lambda: client.apis.kubernetes.get_namespaced_custom_object(
                            cr.metadata.name,
                            cr.metadata.namespace,
                            group=API_GROUP,
                            version=API_VERSION,
                            plural=RESOURCE_KIND_PLURAL,
                        ),
                        retry_count=CONNECTION_RETRY_ATTEMPTS,
                        retry_delay=RETRY_INTERVAL,
                        retry_method="get namespaced custom object",
                        retry_on_exceptions=(
                            NewConnectionError,
                            MaxRetryError,
                            KubernetesError,
                        ),
                    )

                    deployed_cr = CustomResource.decode(
                        SqlmiCustomResource, response
                    )

            if _is_instance_ready(deployed_cr):
                client.stdout("{0} is Ready".format(cr.metadata.name))

    except KubernetesError as e:
        raise SqlmiError(e.message)
    except ValueError as e:
        raise CLIError(e)
    except Exception as e:
        raise CLIError(e)


def arc_sql_mi_edit(
    client,
    name,
    namespace=None,
    path=None,
    cores_limit=None,
    cores_request=None,
    memory_limit=None,
    memory_request=None,
    nowait=False,
    dev=None,
    labels=None,
    annotations=None,
    service_labels=None,
    service_annotations=None,
    agent_enabled=None,
    trace_flags=None,
    use_k8s=None,
):
    """
    Edit the configuration of a SQL managed instance.
    """
    args = locals()
    try:

        if not use_k8s:
            raise ValueError(USE_K8S_EXCEPTION_TEXT)

        check_and_set_kubectl_context()
        namespace = client.namespace

        if path:
            # Read azext_arcdata file for edit
            json_object = FileUtil.read_json(path)
        else:
            json_object = client.apis.kubernetes.get_namespaced_custom_object(
                name=name,
                namespace=namespace,
                group=API_GROUP,
                version=API_VERSION,
                plural=RESOURCE_KIND_PLURAL,
            )

        validate_labels_and_annotations(
            labels, annotations, service_labels, service_annotations, None, None
        )

        cr = CustomResource.decode(SqlmiCustomResource, json_object)
        cr.apply_args(**args)
        cr.validate(client.apis.kubernetes)

        # Patch CR
        client.apis.kubernetes.patch_namespaced_custom_object(
            cr=cr, plural=RESOURCE_KIND_PLURAL
        )

        if nowait:
            client.stdout(
                "Updated {0} in namespace `{1}`. Please use `az sql mi-arc "
                "show -n {0} --k8s-namespace {1} --use-k8s` to check its status.".format(
                    cr.metadata.name, cr.metadata.namespace
                )
            )
        else:
            response = client.apis.kubernetes.get_namespaced_custom_object(
                cr.metadata.name,
                cr.metadata.namespace,
                group=API_GROUP,
                version=API_VERSION,
                plural=RESOURCE_KIND_PLURAL,
            )
            deployed_cr = CustomResource.decode(SqlmiCustomResource, response)

            if not is_windows():
                with AutomaticSpinner(
                    "Updating {0} in namespace `{1}`".format(
                        cr.metadata.name, cr.metadata.namespace
                    ),
                    show_time=True,
                ):
                    while not _is_instance_ready(deployed_cr):
                        if _is_instance_in_error(deployed_cr):
                            client.stdout(
                                "{0} is in error state:{1}".format(
                                    cr.metadata.name,
                                    _get_error_message(deployed_cr),
                                )
                            )
                            break

                        time.sleep(5)
                        response = (
                            client.apis.kubernetes.get_namespaced_custom_object(
                                cr.metadata.name,
                                cr.metadata.namespace,
                                group=API_GROUP,
                                version=API_VERSION,
                                plural=RESOURCE_KIND_PLURAL,
                            )
                        )
                        deployed_cr = CustomResource.decode(
                            SqlmiCustomResource, response
                        )
            else:
                client.stdout(
                    "Updating {0} in namespace `{1}`".format(name, namespace)
                )
                while not _is_instance_ready(deployed_cr):
                    if _is_instance_in_error(deployed_cr):
                        client.stdout(
                            "{0} is in error state:{1}".format(
                                cr.metadata.name,
                                _get_error_message(deployed_cr),
                            )
                        )
                        break

                    time.sleep(5)
                    response = (
                        client.apis.kubernetes.get_namespaced_custom_object(
                            cr.metadata.name,
                            cr.metadata.namespace,
                            group=API_GROUP,
                            version=API_VERSION,
                            plural=RESOURCE_KIND_PLURAL,
                        )
                    )
                    deployed_cr = CustomResource.decode(
                        SqlmiCustomResource, response
                    )

            if _is_instance_ready(deployed_cr):
                client.stdout("{0} is Ready".format(cr.metadata.name))

    except KubernetesError as e:
        raise SqlmiError(e.message)
    except Exception as e:
        raise CLIError(e)


def arc_sql_mi_delete(client, name, namespace=None, use_k8s=None):
    """
    Delete a SQL managed instance.
    """
    try:

        if not use_k8s:
            raise ValueError(USE_K8S_EXCEPTION_TEXT)

        check_and_set_kubectl_context()
        is_valid_connectivity_mode(client)
        namespace = namespace or client.namespace

        client.apis.kubernetes.delete_namespaced_custom_object(
            name=name,
            namespace=namespace,
            group=API_GROUP,
            version=API_VERSION,
            plural=RESOURCE_KIND_PLURAL,
        )

        client.stdout("Deleted {} from namespace {}".format(name, namespace))

    except KubernetesError as e:
        raise SqlmiError(e.message)
    except Exception as e:
        raise CLIError(e)


def arc_sql_mi_show(client, name, path=None, namespace=None, use_k8s=None):
    """
    Show the details of a SQL managed instance.
    """
    try:

        if not use_k8s:
            raise ValueError(USE_K8S_EXCEPTION_TEXT)

        check_and_set_kubectl_context()
        namespace = namespace or client.namespace

        response = client.apis.kubernetes.get_namespaced_custom_object(
            name,
            namespace,
            group=API_GROUP,
            version=API_VERSION,
            plural=RESOURCE_KIND_PLURAL,
        )

        if path:
            if not os.path.isdir(path):
                os.makedirs(path)
            path = os.path.join(path, "{}.json".format(name))
            with open(path, "w") as outfile:
                json.dump(response, outfile, indent=4)
            client.stdout("{0} specification written to {1}".format(name, path))
        else:
            return response

    except KubernetesError as e:
        raise SqlmiError(e.message)
    except Exception as e:
        raise CLIError(e)


def arc_sql_mi_getmirroringcert(
    client, name, cert_file, namespace=None, use_k8s=None
):

    args = locals()
    try:
        if not use_k8s:
            raise ValueError(USE_K8S_EXCEPTION_TEXT)

        check_and_set_kubectl_context()
        namespace = namespace or client.namespace

        json_object = client.apis.kubernetes.get_namespaced_custom_object(
            name=name,
            namespace=namespace,
            group=API_GROUP,
            version=API_VERSION,
            plural=RESOURCE_KIND_PLURAL,
        )
        if not (cert_file):
            raise CLIError("cert_file cannot be null")

        cr = CustomResource.decode(SqlmiCustomResource, json_object)
        cr.apply_args(**args)
        cr.validate(client.apis.kubernetes)

        cr = CustomResource.decode(SqlmiCustomResource, json_object)
        if cr.spec.replicas > 1:
            config_map = kubernetes_util.get_config_map(
                namespace, "sql-config-{0}".format(name)
            )
            data_pem = config_map.data["sql-mirroring-cert"]
            client.stdout(
                "result write to file {0}: {1}".format(cert_file, data_pem)
            )

            file = open(cert_file, "w")
            file.write(data_pem)
            file.close()
        else:
            raise CLIError("More than 1 replica needed MIAA HA scenario.")
    except Exception as e:
        raise CLIError(e)


def arc_sql_mi_list(client, namespace=None, use_k8s=None):
    """
    List SQL managed instances.
    """
    try:
        if not use_k8s:
            raise ValueError(USE_K8S_EXCEPTION_TEXT)

        check_and_set_kubectl_context()
        namespace = namespace or client.namespace

        response = client.apis.kubernetes.list_namespaced_custom_object(
            namespace,
            group=API_GROUP,
            version=API_VERSION,
            plural=RESOURCE_KIND_PLURAL,
        )

        items = response.get("items")

        result = []

        # Temporary, need to discuss what the intended structure is across
        # partners
        for item in items:
            cr = CustomResource.decode(SqlmiCustomResource, item)
            result.append(
                {
                    "name": cr.metadata.name,
                    "primaryEndpoint": cr.status.primaryEndpoint,
                    "replicas": cr.status.readyReplicas,
                    "state": cr.status.state,
                }
            )

        return result

    except KubernetesError as e:
        raise SqlmiError(e.message)
    except Exception as e:
        raise CLIError(e)


def arc_sql_endpoint_list(client, name=None, namespace=None, use_k8s=None):
    """
    List endpoints for the given SQL managed instance(s).
    """
    try:

        if not use_k8s:
            raise ValueError(USE_K8S_EXCEPTION_TEXT)

        check_and_set_kubectl_context()

        namespace = namespace or client.namespace

        custom_resources = []

        if name:
            response = client.apis.kubernetes.get_namespaced_custom_object(
                name,
                namespace,
                group=API_GROUP,
                version=API_VERSION,
                plural=RESOURCE_KIND_PLURAL,
            )
            cr = CustomResource.decode(SqlmiCustomResource, response)
            if cr is None:
                raise CLIError(
                    "SQL managed instance {} not found.".format(name)
                )
            custom_resources.append(cr)
        else:
            response = client.apis.kubernetes.list_namespaced_custom_object(
                namespace,
                group=API_GROUP,
                version=API_VERSION,
                plural=RESOURCE_KIND_PLURAL,
            )

            items = response.get("items")

            for item in items:
                cr = CustomResource.decode(SqlmiCustomResource, item)
                if cr:
                    custom_resources.append(cr)

        arc_sql_endpoints = {"namespace": namespace}
        instances = []

        # Loop through the specified custom resources and retrieve their
        # endpoints from their status
        for cr in custom_resources:
            endpoints = []

            if cr.status:
                descrip_str = "description"
                endpoint_str = "endpoint"

                # Connection string
                ext_endpoint = cr.status.primaryEndpoint
                if ext_endpoint:
                    connection_str = ext_endpoint
                else:
                    connection_str = "Not yet available"
                endpoints.append(
                    {
                        descrip_str: "SQL Managed Instance",
                        endpoint_str: connection_str,
                    }
                )

                # Logs
                logs_endpoint = cr.status.log_search_dashboard
                endpoints.append(
                    {
                        descrip_str: "Log Search Dashboard",
                        endpoint_str: logs_endpoint,
                    }
                )

                # Metrics
                metrics_endpoint = cr.status.metrics_dashboard
                endpoints.append(
                    {
                        descrip_str: "Metrics Dashboard",
                        endpoint_str: metrics_endpoint,
                    }
                )

                # Readable Secondary Endpoint
                secondary_service_endpoint = cr.status.secondaryServiceEndpoint
                if secondary_service_endpoint:
                    endpoints.append(
                        {
                            descrip_str: "SQL Managed Instance Readable "
                            "Secondary Replicas",
                            endpoint_str: secondary_service_endpoint,
                        }
                    )

            instances.append({"name": cr.metadata.name, "endpoints": endpoints})

        arc_sql_endpoints["instances"] = instances

        return arc_sql_endpoints

    except KubernetesError as e:
        raise CLIError(e.message)
    except Exception as e:
        raise CLIError(e)


def arc_sql_mi_config_init(client, path):
    """
    Returns a package of crd.json and spec-template.json.
    """
    try:
        if not os.path.isdir(path):
            os.makedirs(path, exist_ok=True)

        with open(SQLMI_CRD, "r") as stream:
            crd_content = yaml.safe_load(stream)
            crd_pretty = json.dumps(crd_content, indent=4)
            with open(os.path.join(path, "crd.json"), "w") as output:
                output.write(crd_pretty)

        # Copy spec.json template to the new path
        shutil.copy(SQLMI_SPEC, os.path.join(path, "spec.json"))

        client.stdout(
            "{0} templates created in directory: {1}".format(RESOURCE_KIND, path)
        )

    except Exception as e:
        raise CLIError(e)


def arc_sql_mi_config_add(client, path, json_values):
    """
    Add new key and value to the given config file
    """
    try:
        client.add_configuration(path, json_values)
    except Exception as e:
        raise CLIError(e)


def arc_sql_mi_config_replace(client, path, json_values):
    """
    Replace the value of a given key in the given config file
    """
    try:
        client.replace_configuration(path, json_values)
    except Exception as e:
        raise CLIError(e)


def arc_sql_mi_config_remove(client, path, json_path):
    """
    Remove a key from the given config file
    """
    try:
        client.remove_configuration(path, json_path)
    except Exception as e:
        raise CLIError(e)


def arc_sql_mi_config_patch(client, path, patch_file):
    """
    Patch a given file against the given config file
    """
    try:
        client.patch_configuration(path, patch_file)
    except Exception as e:
        raise CLIError(e)


def _is_instance_ready(cr):
    """
    Verify that the SQL Mi instance is ready
    :param cr: Instance to check the readiness of
    :return: True if the instance is ready, False otherwise
    """
    return cr.metadata.generation == cr.status.observed_generation and (
        cr.status.state is not None and cr.status.state.lower() == "ready"
    )


def _is_instance_in_error(cr):
    """
    Check that the SQL Mi instance is in error state
    :param cr: Instance to check the readiness of
    :return: True if the instance is in error, False otherwise
    """
    return cr.status.state is not None and cr.status.state.lower() == "error"


def _get_error_message(cr):
    """
    Get error message from the status of custom resource
    :param cr: Instance to get error message.
    """
    return cr.status.message


def CustomResourceFuntion(client, cr):
    state = None
    results = None

    if client.apis.kubernetes.namespaced_custom_object_exists(
        cr.metadata.name,
        cr.metadata.namespace,
        group=DAG_API_GROUP,
        version=DAG_API_VERSION,
        plural=DAG_RESOURCE_KIND_PLURAL,
    ):
        raise ValueError(
            "Rest API DAG Function API `{}` already exists in namespace `{}`.".format(
                cr.metadata.name, cr.metadata.namespace
            )
        )

    # Create custom resource
    #
    retry(
        lambda: client.apis.kubernetes.create_namespaced_custom_object(
            cr=cr, plural=DAG_RESOURCE_KIND_PLURAL, ignore_conflict=True
        ),
        retry_count=CONNECTION_RETRY_ATTEMPTS,
        retry_delay=RETRY_INTERVAL,
        retry_method="create namespaced custom object",
        retry_on_exceptions=(
            NewConnectionError,
            MaxRetryError,
            KubernetesError,
        ),
    )

    client.stdout("waiting...")
    state = None
    if not is_windows():
        with AutomaticSpinner(
            "Deploying {0} in namespace `{1}`".format(
                cr.metadata.name, cr.metadata.namespace
            ),
            show_time=True,
        ):
            while state != "succeeded" and state != "failed" or state is None:
                time.sleep(5)
                response = retry(
                    lambda: client.apis.kubernetes.get_namespaced_custom_object(
                        cr.metadata.name,
                        cr.metadata.namespace,
                        group=DAG_API_GROUP,
                        version=DAG_API_VERSION,
                        plural=DAG_RESOURCE_KIND_PLURAL,
                    ),
                    retry_count=CONNECTION_RETRY_ATTEMPTS,
                    retry_delay=RETRY_INTERVAL,
                    retry_method="get namespaced custom object",
                    retry_on_exceptions=(
                        NewConnectionError,
                        MaxRetryError,
                        KubernetesError,
                    ),
                )

                deployed_cr = CustomResource.decode(DagCustomResource, response)
                state = deployed_cr.status.state
                results = deployed_cr.status.results
                if state is not None:
                    state = state.lower()
    else:
        client.stdout(
            "Deploying {0} in namespace `{1}`".format(name, namespace)
        )
        while state != "succeeded" and state != "failed" or state is None:
            time.sleep(5)
            response = retry(
                lambda: client.apis.kubernetes.get_namespaced_custom_object(
                    cr.metadata.name,
                    cr.metadata.namespace,
                    group=DAG_API_GROUP,
                    version=DAG_API_VERSION,
                    plural=DAG_RESOURCE_KIND_PLURAL,
                ),
                retry_count=CONNECTION_RETRY_ATTEMPTS,
                retry_delay=RETRY_INTERVAL,
                retry_method="get namespaced custom object",
                retry_on_exceptions=(
                    NewConnectionError,
                    MaxRetryError,
                    KubernetesError,
                ),
            )

            deployed_cr = CustomResource.decode(DagCustomResource, response)
            state = deployed_cr.status.state
            results = deployed_cr.status.results
            if state is not None:
                state = state.lower()

    client.stdout("{0} is Ready".format(cr.metadata.name))

    return state, results


"""
Create Distributed Availability Group between two sql mi instances.
:param client:
:param path:  The path to the src file for the SQL DAG json file.
:param name: The name of the DAG Custom Resource.
:param dag_name: The name of the DAG Name.
:param local_name: The name of the local SQL MI instance name.
:param local_primary: True or False: True indicates local SQL MI Instance is primary.
:param remote_name: The name of the remote SQL MI instance name.
:param remote_cert_file: the file name for remote SQL MI mirroring endpoint certficate.
:return:
"""


def arc_sql_mi_dag_create(
    client,
    name,
    dag_name,
    local_name,
    local_primary,
    remote_name,
    remote_url,
    remote_cert_file,
    namespace=None,
    path=None,
    use_k8s=None,
):

    args = locals()
    try:
        if not use_k8s:
            raise ValueError(USE_K8S_EXCEPTION_TEXT)
        check_and_set_kubectl_context()
        namespace = namespace or client.namespace

        # Determine source for the resource spec preferring path first
        #
        if not path:
            # TODO: Use mutating web hooks to set these default values
            #
            spec_object = {
                "apiVersion": DAG_API_GROUP + "/" + DAG_API_VERSION,
                "kind": DAG_RESOURCE_KIND,
                "metadata": {"name": name},
                "spec": {
                    "input": {
                        "dagName": dag_name,
                        "localName": local_name,
                        "remoteName": remote_name,
                        "remoteEndpoint": remote_url,
                        "remotePublicCert": "",
                        "isLocalPrimary": local_primary,
                    }
                },
            }

        # Otherwise, use the provided src file.
        #
        else:
            spec_object = FileUtil.read_json(path)

        # Decode base spec and apply args. Must patch namespace in separately since it's not parameterized in this func
        #
        cr = CustomResource.decode(DagCustomResource, spec_object)
        cr.metadata.namespace = namespace
        cr.validate(client.apis.kubernetes)

        file = open(remote_cert_file, "r")
        remotePublicCert = file.read()
        file.close()

        cr.spec.input.remotePublicCert = remotePublicCert

        client.stdout(
            "create_namespaced_custom_object {0}".format(cr._to_dict())
        )

        state, results = CustomResourceFuntion(client, cr)

        if state != "succeeded":
            raise CLIError(
                "Create Distributed AG return state({0}), result({1})".format(
                    state, results
                )
            )

    except Exception as e:
        raise CLIError(e)


"""
Delete Distributed Availability Group by deleting DAG custom resource.
:param client:
:param name: The name of the DAG Custom Resource.
:return:
"""


def arc_sql_mi_dag_delete(client, name, namespace=None, use_k8s=None):

    args = locals()
    try:
        if not use_k8s:
            raise ValueError(USE_K8S_EXCEPTION_TEXT)
        check_and_set_kubectl_context()
        namespace = namespace or client.namespace

        if not (name):
            raise CLIError("name {0} cannot be null".format(name))

        client.apis.kubernetes.delete_namespaced_custom_object(
            name=name,
            namespace=namespace,
            group=DAG_API_GROUP,
            version=DAG_API_VERSION,
            plural=DAG_RESOURCE_KIND_PLURAL,
        )
        client.stdout(
            "Deleted dag {} from namespace {}".format(name, namespace)
        )

    except Exception as e:
        raise CLIError(e)


"""
Get custom resource spec for a Distributed Availability Group
:param client:
:param name: The name of the DAG Custom Resource.
:return:
"""


def arc_sql_mi_dag_get(client, name, namespace=None, use_k8s=None):
    try:
        if not use_k8s:
            raise ValueError(USE_K8S_EXCEPTION_TEXT)
        check_and_set_kubectl_context()
        namespace = namespace or client.namespace
        response = client.apis.kubernetes.get_namespaced_custom_object(
            name,
            namespace,
            group=DAG_API_GROUP,
            version=DAG_API_VERSION,
            plural=DAG_RESOURCE_KIND_PLURAL,
        )
        cr = CustomResource.decode(DagCustomResource, response)
        client.stdout(
            "input: {}".format(json.dumps(cr.spec.input._to_dict(), indent=4))
        )
        client.stdout(
            "status: {}".format(json.dumps(cr.status._to_dict(), indent=4))
        )
    except Exception as e:
        raise CLIError(e)
