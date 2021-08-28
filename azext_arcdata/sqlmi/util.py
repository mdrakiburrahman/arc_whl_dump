# ------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# ------------------------------------------------------------------------------

from azext_arcdata.kubernetes_sdk.client import K8sApiException
from azext_arcdata.sqlmi.exceptions import SqlmiError
from azext_arcdata.core.constants import DIRECT
from azext_arcdata.core.labels import parse_labels
from azext_arcdata.core.util import retry
from azext_arcdata.sqlmi.constants import (
    SQLMI_PASSWORD_MIN_LENGTH,
    SQLMI_PASSWORD_REQUIRED_GROUPS,
)

from azext_arcdata.core.constants import (
    ARC_GROUP,
    DATA_CONTROLLER_CRD_VERSION,
    DATA_CONTROLLER_PLURAL,
)

from azext_arcdata.sqlmi.constants import (
    SQLMI_LICENSE_TYPES,
    SQLMI_TIERS,
)

from azext_arcdata.core.util import (
    retry,
    get_config_from_template,
)

from collections import OrderedDict
from urllib3.exceptions import NewConnectionError, MaxRetryError
from knack.cli import CLIError

import base64
import os
import pem
import re
import yaml

CONNECTION_RETRY_ATTEMPTS = 12
RETRY_INTERVAL = 5


def is_valid_sql_password(pw, user):
    """
    Checks if the provided pw is a valid sql server password i.e. is at least
    eight characters long and contains a char from at least three of these
    groups
    -Uppercase letters
    -Lowercase letters
    -Base 10 digits
    -Non-alphanumeric characters
    :param pw: the password
    :param user: username for the sql instance
    :return: True if pw meets requirements, False otherwise
    """
    if not pw:
        return False

    if user in pw:
        return False

    if len(pw) < SQLMI_PASSWORD_MIN_LENGTH:
        return False

    lower = 0
    upper = 0
    special = 0
    digit = 0

    for c in pw:
        if c.isdigit():
            digit = 1
        elif c.isalpha():
            if c.isupper():
                upper = 1
            else:
                lower = 1
        else:
            # Assume any other characters qualify as 'special' characters.
            # Work item to implement stricter policies: #1282103
            #
            special = 1

    return (lower + upper + special + digit) >= SQLMI_PASSWORD_REQUIRED_GROUPS


def order_endpoints():
    """
    Order SQL instance `dict` sections to the same order the server API handed us.
    NOTE: This is redundant in Python 3.7 however needed for earlier versions.

    :return: A well defined `OrderedDict` of the given SQL instance endpoints.
    """

    def get_endpoints(endpoints):
        """
        Creates ordered dictionaries for the given endpoints to be used in the
        BoxLayout.
        :param endpoints:
        """

        def new_endpoint(e):
            return OrderedDict(
                [
                    ("description", e["description"]),
                    ("endpoint", e["endpoint"]),
                    ("options", []),
                ]
            )

        return [new_endpoint(endpoint) for endpoint in endpoints]

    def get_instances(obj):
        """
        Returns all instances and their endpoints.
        :param obj:
        :return:
        """
        obj = obj if obj else []
        return [
            OrderedDict(
                [
                    ("instanceName", instance["name"]),
                    ("endpoints", get_endpoints(instance.get("endpoints"))),
                ]
            )
            for instance in obj
        ]

    def get_arc_sql_endpoints(obj):
        """
        Retrieves all SQL instance endpoints in an ordered dictionary to be
        used in the BoxLayout.
        :param obj:
        """
        return (
            None
            if "namespace" not in obj
            else OrderedDict(
                [
                    ("clusterName", obj["namespace"]),
                    ("instance", get_instances(obj["instances"])),
                ]
            )
        )

    return get_arc_sql_endpoints


def hierarchical_output(command_result):
    """
    Callback for formatting complex custom-output.
    :parm_am command_result: The command's high-level result object.
    :return: Complex BoxLayout otherwise flat json.
    """
    from azext_arcdata.core.layout import BoxLayout

    try:

        # raw_result = command_result.result
        raw_result = command_result
        # result = order_endpoints()(raw_result)
        result = command_result
        print(result)
        return BoxLayout(
            result,
            config={
                "headers": {
                    "left": {"label": "", "id": None},
                    "right": {"label": "", "id": None},
                },
                "identifiers": [],
            },
            bdc_config=True,
        )
    except Exception:  # -- fallback --
        from knack.output import format_json
    return format_json(command_result)


def is_valid_connectivity_mode(client):
    CONNECTION_RETRY_ATTEMPTS = 12
    RETRY_INTERVAL = 5

    # FIX
    namespace = client.namespace

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
            "No data controller exists in Kubernetes namespace `{}`.".format(
                namespace
            )
        )
    else:
        # Checks if connectivity mode is valid (only indirect mode is allowed)
        #
        if dcs[0]["spec"]["settings"]["azure"]["connectionMode"] == DIRECT:
            raise SqlmiError(
                "Performing this action from az using the --use-k8s parameter is only allowed using "
                "indirect mode. Please use the Azure Portal to perform this "
                "action in direct connectivity mode."
            )


def get_valid_sql_license_types():
    """
    Get the valid sql license types
    """
    return SQLMI_LICENSE_TYPES


def get_valid_sql_tiers():
    """
    Get the valid sql tiers
    """
    return SQLMI_TIERS


def validate_sqlmi_tier(tier):
    """
    returns True if tier is valid
    """

    # tier should have a default value
    if tier is None:
        return False

    # if tier was provided, make sure it's within the allowed values
    # (case insensitive)
    if tier.lower() in (t.lower() for t in get_valid_sql_tiers()):
        return True

    return False


def validate_sqlmi_license_type(license_type):
    """
    returns True if license type is valid
    """

    # license_type should have a default value
    if license_type is None:
        return False

    # if license_type was provided, make sure it's within the allowed values
    # (case insensitive)
    if license_type.lower() in (
        t.lower() for t in get_valid_sql_license_types()
    ):
        return True

    return False


def validate_labels_and_annotations(
    labels,
    annotations,
    service_labels,
    service_annotations,
    storage_labels,
    storage_annotations,
):
    if labels:
        try:
            parse_labels(labels)
        except ValueError as e:
            raise CLIError("Labels invalid: {e}")

    if annotations:
        try:
            parse_labels(annotations)
        except ValueError as e:
            raise CLIError("Annotations invalid: {e}")

    if service_labels:
        try:
            parse_labels(service_labels)
        except ValueError as e:
            raise CLIError("Service labels invalid: {e}")

    if service_annotations:
        try:
            parse_labels(service_annotations)
        except ValueError as e:
            raise CLIError("Service annotations invalid: {e}")

    if storage_labels:
        try:
            parse_labels(storage_labels)
        except ValueError as e:
            raise CLIError("Storage labels invalid: {e}")

    if storage_annotations:
        try:
            parse_labels(storage_annotations)
        except ValueError as e:
            raise CLIError("Storage annotations invalid: {e}")


def parse_cert_files(certificate_public_key_file, certificate_private_key_file):
    """
    parses certificate and private key files and returns the values.
    """
    if not os.path.exists(certificate_public_key_file) or not os.path.isfile(
        certificate_public_key_file
    ):
        raise ValueError(
            "Certificate public key file '"
            + certificate_public_key_file
            + "' does not exist."
        )

    if not os.path.exists(certificate_private_key_file) or not os.path.isfile(
        certificate_private_key_file
    ):
        raise ValueError(
            "Certificate private key file '"
            + certificate_private_key_file
            + "' does not exist."
        )

    # Read certificate files.
    #
    with open(certificate_public_key_file) as f:
        cert_public_key = f.read()

    with open(certificate_private_key_file) as f:
        cert_private_key = f.read()

    # Validate PEM format.
    #
    try:
        parsed_certificates = pem.parse(bytes(cert_public_key, "utf-8"))
    except:
        raise ValueError(
            "Certificate public key does not have a valid PEM format."
        )

    if len(parsed_certificates) != 1:
        raise ValueError(
            "Certificate public key file '"
            + certificate_public_key_file
            + "' must contain one and only one valid PEM formatted certificate."
        )

    try:
        parsed_privatekeys = pem.parse(bytes(cert_private_key, "utf-8"))
    except:
        raise ValueError(
            "Certificate private key does not have a valid PEM format."
        )

    if len(parsed_privatekeys) != 1:
        raise ValueError(
            "Certificate private key file '"
            + certificate_private_key_file
            + "' must contain one and only one valid PEM formatted private key."
        )

    # Ensure that certificate is of type pem._core.Certificate and private key is of
    # type pem._core.RSAPrivateKey.
    #
    if not isinstance(parsed_certificates[0], pem._core.Certificate):
        raise ValueError(
            "Certificate data in file '"
            + certificate_public_key_file
            + "' must have a valid PEM formatted certificate."
        )

    if not isinstance(parsed_privatekeys[0], pem._core.RSAPrivateKey):
        raise ValueError(
            "Private key data in file '"
            + certificate_private_key_file
            + "' must have a valid PEM formatted private key."
        )

    return (cert_public_key, cert_private_key)


def validate_admin_login_secret(client, namespace, admin_login_secret):
    """
    validates the given admin login secret.
    """
    username_entry_in_secret = "username"
    password_entry_in_secret = "password"

    # Load secret and validate contents.
    #
    k8s_secret = retry(
        lambda: client.apis.kubernetes.get_secret(
            namespace, admin_login_secret
        ),
        retry_count=CONNECTION_RETRY_ATTEMPTS,
        retry_delay=RETRY_INTERVAL,
        retry_method="get secret",
        retry_on_exceptions=(
            NewConnectionError,
            MaxRetryError,
            K8sApiException,
        ),
    )

    secret_data = k8s_secret.data

    # Check if username and password entries exist
    # in the secret.
    #
    if (
        not username_entry_in_secret in secret_data
        or not password_entry_in_secret in secret_data
    ):
        raise ValueError(
            "Kubernetes secret '"
            + admin_login_secret
            + "' must have keys '"
            + username_entry_in_secret
            + "' and '"
            + password_entry_in_secret
            + "' in it."
        )

    # Read data and validate.
    #
    username_data = base64.b64decode(secret_data[username_entry_in_secret])
    password_data = base64.b64decode(secret_data[password_entry_in_secret])

    username = str(username_data, "utf-8")
    password = str(password_data, "utf-8")

    # Validate username is not sa.
    #
    if username == "sa":
        raise ValueError(
            "Login 'sa' is not allowed as username in secret '"
            + admin_login_secret
            + "'."
        )

    # Validate password complexity.
    #
    if not is_valid_sql_password(password, username):
        raise ValueError(
            "SQL Server passwords must be at "
            "least 8 characters long, cannot contain the "
            "username, and must contain characters from "
            "three of the following four sets: Uppercase "
            "letters, Lowercase letters, Base 10 digits, "
            "and Symbols."
        )


def validate_certificate_secret(client, namespace, service_certificate_secret):
    """
    validates the given service certificate secret.
    """
    certificate_entry_in_secret = "certificate.pem"
    privatekey_entry_in_secret = "privatekey.pem"

    # Load secret and validate contents.
    #
    k8s_secret = retry(
        lambda: client.apis.kubernetes.get_secret(
            namespace, service_certificate_secret
        ),
        retry_count=CONNECTION_RETRY_ATTEMPTS,
        retry_delay=RETRY_INTERVAL,
        retry_method="get secret",
        retry_on_exceptions=(
            NewConnectionError,
            MaxRetryError,
            K8sApiException,
        ),
    )

    secret_data = k8s_secret.data

    # Check if certificate and privatekey entries exist
    # in the secret.
    #
    if (
        not certificate_entry_in_secret in secret_data
        or not privatekey_entry_in_secret in secret_data
    ):
        raise ValueError(
            "Kubernetes secret '"
            + service_certificate_secret
            + "' must have keys '"
            + certificate_entry_in_secret
            + "' and '"
            + privatekey_entry_in_secret
            + "' in it."
        )

    # Read data and ensure correct PEM format.
    #
    certificate_data = base64.b64decode(
        secret_data[certificate_entry_in_secret]
    )
    privatekey_data = base64.b64decode(secret_data[privatekey_entry_in_secret])

    try:
        parsed_certificates = pem.parse(certificate_data)
    except:
        raise ValueError(
            "Certificate data in secret '"
            + service_certificate_secret
            + "' does not have a valid PEM format."
        )

    try:
        parsed_privatekeys = pem.parse(privatekey_data)
    except:
        raise ValueError(
            "Private key data in secret '"
            + service_certificate_secret
            + "' does not have a valid PEM format."
        )

    # Ensure single certificate and private key exist.
    #
    if len(parsed_certificates) != 1:
        raise ValueError(
            "Certificate data in secret '"
            + service_certificate_secret
            + "' must have one and only one valid PEM formatted certificate."
        )
    if len(parsed_privatekeys) != 1:
        raise ValueError(
            "Private key data in secret '"
            + service_certificate_secret
            + "' must have one and only one valid PEM formatted private key."
        )

    # Ensure that certificate is of type pem._core.Certificate and private key is of
    # type pem._core.RSAPrivateKey.
    #
    if not isinstance(parsed_certificates[0], pem._core.Certificate):
        raise ValueError(
            "Certificate data in secret '"
            + service_certificate_secret
            + "' must have a valid PEM formatted certificate."
        )

    if not isinstance(parsed_privatekeys[0], pem._core.RSAPrivateKey):
        raise ValueError(
            "Private key data in secret '"
            + service_certificate_secret
            + "' must have a valid PEM formatted private key."
        )


def create_certificate_secret(
    client,
    namespace,
    service_certificate_secret,
    cert_public_key,
    cert_private_key,
):
    """
    creates a secret in Kubernetes to store service certificate.
    """

    secret_model = dict()
    encoding = "utf-8"
    secret_model["secretName"] = service_certificate_secret
    secret_model["base64Certificate"] = base64.b64encode(
        bytes(cert_public_key, encoding)
    ).decode(encoding)
    secret_model["base64PrivateKey"] = base64.b64encode(
        bytes(cert_private_key, encoding)
    ).decode(encoding)
    temp = get_config_from_template(
        os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            "templates",
            "service-certificate.yaml.tmpl",
        ),
        secret_model,
    )
    mssql_certificate_secret = yaml.safe_load(temp)

    try:
        retry(
            lambda: client.apis.kubernetes.create_secret(
                namespace,
                mssql_certificate_secret,
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


def check_secret_exists_with_retries(client, namespace, secret):
    """
    Check if a k8s secret exists with retries.
    """

    return retry(
        lambda: client.apis.kubernetes.secret_exists(namespace, secret),
        retry_count=CONNECTION_RETRY_ATTEMPTS,
        retry_delay=RETRY_INTERVAL,
        retry_method="secret exists",
        retry_on_exceptions=(
            NewConnectionError,
            MaxRetryError,
            K8sApiException,
        ),
    )
