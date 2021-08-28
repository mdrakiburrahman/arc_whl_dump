# ------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# -----------------------------------------------------------------------------

from azext_arcdata.core.cli_client import CliClient
from azext_arcdata.core.util import DeploymentConfigUtil


__all__ = ["beget"]


def beget(az_cli, kwargs):
    """Client factory"""
    return PostgresClientMixin(az_cli, namespace=kwargs.get("namespace"))


def beget_no_check_auth(az_cli, _):
    """Client factory - no check on authentication"""
    return PostgresClientMixin(az_cli, check_namespace=False)


class PostgresClientMixin(CliClient):
    def __init__(self, az_cli, namespace=None, check_namespace=True):
        super(PostgresClientMixin, self).__init__(
            az_cli, namespace=namespace, check_namespace=check_namespace
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
