# ------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# ------------------------------------------------------------------------------

from azext_arcdata.kubernetes_sdk.client import KubernetesClient
from azext_arcdata.dc.constants import CONTROLLER_SVC
from azext_arcdata.core.prompt import prompt_y_n
from azext_arcdata.core.util import (
    check_and_set_kubectl_context,
    retry,
    BOOLEAN_STATES
)
from urllib3.exceptions import NewConnectionError, MaxRetryError
from kubernetes.client.rest import ApiException as K8sApiException
from knack.prompting import NoTTYException
from knack.log import get_logger
from knack.cli import CLIError
from requests.exceptions import SSLError

import requests
import json
import os

__all__ = ["ControllerClient"]

logger = get_logger(__name__)


class ControllerClient(object):
    def __init__(self):
        self._kubernetes_client = KubernetesClient()

    def get_export_file_path(self, file_path, controller_endpoint):
        def _get_export_file_path(verify=True):

            uri = "{endpoint}/api/v{version}/export/{file_path}".format(
                endpoint=controller_endpoint, version=1, file_path=file_path
            )
            logger.debug("EXPORT FILE PATH URI: %s", uri)
            logger.debug("SSL certificate verification: %s", verify)

            return json.loads(requests.get(uri, verify=verify).text)

        verify_ssl = os.environ.get("AZDATA_VERIFY_SSL")
        logger.debug("AZDATA_VERIFY_SSL: %s", verify_ssl)

        if verify_ssl is None:
            try:
                return _get_export_file_path()
            except SSLError as e:
                logger.debug(e)

                try:
                    bypass = prompt_y_n("Bypass server certificate check:")
                except NoTTYException:
                    raise CLIError("Specify environment variable "
                                   "'AZDATA_VERIFY_SSL=yes|no' for "
                                   "non-interactive mode.")

                if not bypass:
                    logger.debug("You have opted to require the server "
                                 "certificate check, aborting.")
                    raise CLIError(e)

                logger.warn(
                    "You have opted to bypass the server certificate check."
                )

                return _get_export_file_path(verify=False)

        else:
            return _get_export_file_path(verify=BOOLEAN_STATES.get(verify_ssl))

    def get_endpoint(self, namespace):
        check_and_set_kubectl_context()

        connection_retry_attempts = 12
        retry_interval = 5

        service = retry(
            lambda: self._kubernetes_client.get_service(
                namespace, CONTROLLER_SVC
            ),
            retry_count=connection_retry_attempts,
            retry_delay=retry_interval,
            retry_method="get service",
            retry_on_exceptions=(
                NewConnectionError,
                MaxRetryError,
                K8sApiException,
            ),
        )
        logger.debug(service)

        endpoint = retry(
            lambda: self._kubernetes_client.get_service_endpoint(
                namespace, service
            ),
            retry_count=connection_retry_attempts,
            retry_delay=retry_interval,
            retry_method="get service endpoint",
            retry_on_exceptions=(
                NewConnectionError,
                MaxRetryError,
                K8sApiException,
            ),
        )
        logger.debug("Controller Endpoint: %s", endpoint)

        return endpoint
