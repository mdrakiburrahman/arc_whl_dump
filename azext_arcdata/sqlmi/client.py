# ------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# ------------------------------------------------------------------------------

import time

from azext_arcdata.core.cli_client import CliClient
from azext_arcdata.core.util import DeploymentConfigUtil, retry
from azext_arcdata.kubernetes_sdk.client import KubernetesError
from azext_arcdata.kubernetes_sdk.models.custom_resource import CustomResource
from azext_arcdata.sqlmi.constants import (
    DAG_API_GROUP,
    DAG_API_VERSION,
    DAG_RESOURCE_KIND_PLURAL,
)
from azext_arcdata.sqlmi.models.dag_cr import DagCustomResource
from azext_arcdata.sqlmi.util import CONNECTION_RETRY_ATTEMPTS, RETRY_INTERVAL
from urllib3.exceptions import MaxRetryError, NewConnectionError

__all__ = ["beget"]


def beget(az_cli, kwargs):
    """
    Client factory
    """
    return SqlmiClientMixin(az_cli, kwargs)


def beget_no_namespace(az_cli, kwargs):
    """
    Client factory - no check on namespace
    """
    return SqlmiClientMixin(az_cli, kwargs, check_namespace=False)


class SqlmiClientMixin(CliClient):
    def __init__(self, az_cli, kwargs, check_namespace=True):
        super(SqlmiClientMixin, self).__init__(
            az_cli, kwargs, check_namespace=check_namespace
        )

    @staticmethod
    def add_configuration(path, json_values):
        config_object = DeploymentConfigUtil.config_add(path, json_values)
        DeploymentConfigUtil.write_config_file(path, config_object)

    @staticmethod
    def replace_configuration(path, json_values):
        config_object = DeploymentConfigUtil.config_replace(path, json_values)
        DeploymentConfigUtil.write_config_file(path, config_object)

    @staticmethod
    def remove_configuration(path, json_path):
        config_object = DeploymentConfigUtil.config_remove(path, json_path)
        DeploymentConfigUtil.write_config_file(path, config_object)

    @staticmethod
    def patch_configuration(path, patch_file):
        config_object = DeploymentConfigUtil.config_patch(path, patch_file)
        DeploymentConfigUtil.write_config_file(path, config_object)

    def create_dag(self, cr):
        results = None

        if self.apis.kubernetes.namespaced_custom_object_exists(
            cr.metadata.name,
            cr.metadata.namespace,
            group=DAG_API_GROUP,
            version=DAG_API_VERSION,
            plural=DAG_RESOURCE_KIND_PLURAL,
        ):
            raise ValueError(
                "Rest API DAG Function API `{}` already exists in "
                "namespace `{}`.".format(
                    cr.metadata.name, cr.metadata.namespace
                )
            )

        # Create custom resource
        #
        retry(
            lambda: self.apis.kubernetes.create_namespaced_custom_object(
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

        state = None
        while state != "succeeded" and state != "failed" or state is None:
            time.sleep(5)
            response = retry(
                lambda: self.apis.kubernetes.get_namespaced_custom_object(
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

        return state, results
