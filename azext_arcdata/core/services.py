# ------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# ------------------------------------------------------------------------------

"""
Service interface to all data-sources:
- Cloud uses ARM apis
- Kubernetes-native apis
"""

from azext_arcdata.core.output import OutputStream
from azext_arcdata.core.util import DeploymentConfigUtil
from azext_arcdata.kubernetes_sdk.dc.debug import copy_debug_logs, take_dump
from azure.cli.core._profile import Profile
from abc import ABCMeta, abstractmethod
from knack.log import get_logger
from six import add_metaclass

import os

__all__ = ["beget_service"]

logger = get_logger(__name__)


def beget_service(az_cli):
    """
    The factory function used to handel common `service proxies` to the
    different data sources for direct and indirect mode.

    commands's command group.
    :return: A named tuple with dot notation to the service groups.
    """

    command = az_cli.data.get("command")
    use_k8s = az_cli.data.get("arcdata_command_args").get("use_k8s", "noopt")

    # -- assemble base command group for runtime factory type --
    dispatch = " ".join(command.split(" ")[0:2])
    if use_k8s:
        dispatch += " noopt" if use_k8s == "noopt" else " --use-k8s"

    logger.debug("Service dispatch key: '%s'", dispatch)

    service = {
        "arcdata dc": ArmDataControllerServiceProxy,
        "arcdata dc --use-k8s": KubernetesDataControllerServiceProxy,
        "arcdata dc noopt": NoOptDataControllerServiceProxy,
        "arcdata ad-connector": ArmActiveDirectoryConnectorServiceProxy,
        "arcdata ad-connector --use-k8s": KubernetesActiveDirectoryConnectorServiceProxy,
        "sql mi-arc": ArmManagedInstanceServiceProxy,
        "sql mi-arc --use-k8s": KubernetesManagedInstanceServiceProxy,
        "sql midb-arc": ArmManagedInstanceServiceProxy,
        "sql midb-arc --use-k8s": KubernetesManagedInstanceServiceProxy,
        "postgres arc-server": ArmPostgresServiceProxy,
        "postgres arc-server --use-k8s": KubernetesPostgresServiceProxy,
    }.get(dispatch)(az_cli)

    logger.debug("Runtime mode [--use-k8s]: %s", use_k8s)
    logger.debug("Service proxy type: %s", type(service).__name__)
    logger.debug("Public service handle name: %s", service.name)

    return service


# ============================================================================ #
# ============================================================================ #
# ============================================================================ #


@add_metaclass(ABCMeta)
class BaseServiceProxy(object):
    def __init__(self, name):
        self._name = name

    @property
    def name(self):
        return self._name

    @property
    def stdout(self):
        return OutputStream().stdout.write

    @property
    def stderr(self):
        return OutputStream().stderr.write

    @staticmethod
    def get_crd_file_dict():
        import azext_arcdata.kubernetes_sdk.dc.constants as dc_constants

        return {
            "PostgreSql": dc_constants.POSTGRES_CRD,
            "SqlManagedInstance": dc_constants.SQLMI_CRD,
            "SqlManagedInstanceRestoreTask": dc_constants.SQLMI_RESTORE_TASK_CRD,
            "ExportTask": dc_constants.EXPORT_TASK_CRD,
            "FailoverGroup": dc_constants.FOG_CRD,
            "ActiveDirectoryConnector": dc_constants.ACTIVE_DIRECTORY_CONNECTOR_CRD,
            "Monitor": dc_constants.MONITOR_CRD,
            "DataController": dc_constants.DATA_CONTROLLER_CRD,
        }

    @staticmethod
    def get_spec_file_dict():
        import azext_arcdata.kubernetes_sdk.dc.constants as dc_constants

        return {
            "PostgreSql": dc_constants.POSTGRES_SPEC,
            "SqlManagedInstance": dc_constants.SQLMI_SPEC,
            "SqlManagedInstanceRestoreTask": dc_constants.SQLMI_RESTORE_TASK_SPEC,
            "ExportTask": dc_constants.EXPORT_TASK_SPEC,
            "FailoverGroup": dc_constants.FOG_SPEC,
            "ActiveDirectoryConnector": dc_constants.AD_CONNECTOR_SPEC,
            "Monitor": dc_constants.MONITOR_SPEC,
            "DataController": dc_constants.DATA_CONTROLLER_SPEC,
        }

    @staticmethod
    def get_deployment_config_dir():
        from azext_arcdata.kubernetes_sdk.dc.constants import CONFIG_DIR

        return CONFIG_DIR

    @staticmethod
    def get_deployment_config_files():
        from azext_arcdata.kubernetes_sdk.dc.constants import CONFIG_FILES

        return CONFIG_FILES

    @staticmethod
    def list_configs(config_profile=None):
        config_dir = BaseServiceProxy.get_deployment_config_dir()
        configs = DeploymentConfigUtil.config_list(config_dir, config_profile)
        return list(filter(lambda c: "test" not in c, configs))  # Filter test

    def __str__(self):
        """
        Returns the base string representation of attributes. Sub-class should
        override and implement.
        """
        return "<BaseManagedInstanceService>"

    def __repr__(self):
        """For `print` and `pprint`. Sub-class should override and implement."""
        return self.__str__()


# ============================================================================ #
# ============================================================================ #
# ============================================================================ #


@add_metaclass(ABCMeta)
class BaseManagedInstanceServiceProxy(BaseServiceProxy):
    def __init__(self):
        super(BaseManagedInstanceServiceProxy, self).__init__("mi")

    @abstractmethod
    def create(self):
        pass

    @abstractmethod
    def delete(self):
        pass

    @abstractmethod
    def update(self):
        pass

    @abstractmethod
    def list(self):
        pass

    @abstractmethod
    def restore(self):
        pass


# ============================================================================ #
# ============================================================================ #
# ============================================================================ #


@add_metaclass(ABCMeta)
class NoOptDataControllerServiceProxy(BaseServiceProxy):
    def __init__(self, *args, **kwargs):
        super(NoOptDataControllerServiceProxy, self).__init__("dc")

    @staticmethod
    def export_upload_log_and_metrics(command_value_object: tuple):
        from azext_arcdata.arm_sdk.client import ArmClient

        # TODO: build credentials here rather than deep into this call stack
        class NoOptCred(object):
            def get_token(self):
                class NoOptAccessToken(object):
                    token = "noopt"

                return NoOptAccessToken()

        subscription = "noopt"
        arm_client = ArmClient(NoOptCred(), subscription)

        arm_client.export_upload_log_and_metrics_dc(command_value_object.path)


# ============================================================================ #
# ============================================================================ #
# ============================================================================ #


@add_metaclass(ABCMeta)
class BaseDataControllerServiceProxy(BaseServiceProxy):
    def __init__(self):
        super(BaseDataControllerServiceProxy, self).__init__("dc")

    @abstractmethod
    def create(self, command_value_object: tuple):
        pass

    @abstractmethod
    def delete(self, command_value_object: tuple):
        pass

    @abstractmethod
    def upgrade(self, command_value_object: tuple):
        pass

    @abstractmethod
    def list_upgrades(self, command_value_object: tuple):
        pass

    @abstractmethod
    def get_status(self, command_value_object: tuple):
        pass

    @abstractmethod
    def get_config(self, command_value_object: tuple):
        pass


# ============================================================================ #
# ============================================================================ #
# ============================================================================ #


@add_metaclass(ABCMeta)
class ArmMixin(object):
    @staticmethod
    def acquire_arm_client(az_cli):
        from azext_arcdata.arm_sdk.client import ArmClient
        from azure.common.credentials import get_cli_profile

        # Gets the azure subscription by attempting to gather it from:
        # 1. global argument [--subscription] if provided
        # 2. Otherwise active subscription in profile if available
        # 3. Otherwise `None`
        subscription = az_cli.data.get("subscription_id")

        if not subscription:
            try:
                profile = Profile(cli_ctx=az_cli.local_context.cli_ctx)
                subscription = profile.get_subscription_id()
            except Exception:  # pylint:disable=broad-except
                logger.debug("To not see this warning, first login to Azure.")
                pass
        else:
            try:
                profile = Profile(cli_ctx=az_cli.local_context.cli_ctx)
                subscription = profile.get_subscription(
                    subscription=subscription
                ).get("id")
            except Exception:  # pylint:disable=broad-except
                logger.debug("To not see this warning, first login to Azure.")

        logger.debug("Using subscription: %s", subscription)

        (credentials, _, _) = get_cli_profile().get_login_credentials()
        from azext_arcdata.core.identity import ArcDataCliCredential

        cred = ArcDataCliCredential(credentials)

        return ArmClient(cred, subscription)


# ============================================================================ #
# ============================================================================ #
# ============================================================================ #


@add_metaclass(ABCMeta)
class KubernetesMixin(object):
    def __init__(self):
        self.apply_context()

    @property
    def namespace(self):
        from azext_arcdata.core.prompt import prompt
        from azext_arcdata.core.util import load_kube_config

        namespace = load_kube_config().get("namespace")

        if not namespace:
            namespace = prompt("Kubernetes Namespace: ")

        logger.debug("Using Kubernetes namespace = {0}".format(namespace))

        return namespace

    def apply_context(self):
        from azext_arcdata.core.util import check_and_set_kubectl_context

        check_and_set_kubectl_context()


# ============================================================================ #
# ============================================================================ #
# ============================================================================ #


class ArmManagedInstanceServiceProxy(BaseManagedInstanceServiceProxy, ArmMixin):
    def __init__(self, az_cli):
        super(ArmManagedInstanceServiceProxy, self).__init__()

    def create(self, command_value_object: tuple):
        pass

    def delete(self, command_value_object: tuple):
        pass

    def update(self, command_value_object: tuple):
        pass

    def list(self, command_value_object: tuple):
        pass

    def restore(self, command_value_object: tuple):
        pass


# ============================================================================ #
# ============================================================================ #
# ============================================================================ #


class ArmDataControllerServiceProxy(BaseDataControllerServiceProxy, ArmMixin):
    def __init__(self, az_cli):
        super(ArmDataControllerServiceProxy, self).__init__()
        self._arm_client = self.acquire_arm_client(az_cli)

    def create(self, command_value_object: tuple):
        polling = not command_value_object.no_wait
        path = command_value_object.path

        if command_value_object.profile_name:
            config_dir = self.get_deployment_config_dir()
            path = os.path.join(config_dir, command_value_object.profile_name)
            logger.debug("Using profile: %s", command_value_object.profile_name)

        if not os.path.exists(path):
            raise NotADirectoryError(f"Profile not found:\n'{path}'")

        if command_value_object.cluster_name:
            return self._arm_client.create_dc(
                command_value_object.resource_group,
                command_value_object.name,
                command_value_object.custom_location,
                command_value_object.connectivity_mode,
                command_value_object.cluster_name,
                command_value_object.namespace,
                path,
                storage_class=command_value_object.storage_class,
                infrastructure=command_value_object.infrastructure,
                auto_upload_metrics=command_value_object.auto_upload_metrics,
                auto_upload_logs=command_value_object.auto_upload_logs,
                polling=polling,
            )
        else:
            return self._arm_client.__create_depreciated_dc__(
                command_value_object.resource_group,
                command_value_object.name,
                command_value_object.location,
                command_value_object.custom_location,
                command_value_object.connectivity_mode,
                path=path,
                storage_class=command_value_object.storage_class,
                infrastructure=command_value_object.infrastructure,
                auto_upload_metrics=command_value_object.auto_upload_metrics,
                auto_upload_logs=command_value_object.auto_upload_logs,
                polling=polling,
            )

    def update(self, cvo: tuple):
        return self._arm_client.update_dc(
            cvo.resource_group_name,
            cvo.name,
            auto_upload_logs=cvo.auto_upload_logs,
            auto_upload_metrics=cvo.auto_upload_metrics,
        )

    def delete(self, command_value_object: tuple):
        polling = not command_value_object.no_wait
        return self._arm_client.delete_dc(
            command_value_object.resource_group,
            command_value_object.name,
            polling=polling,
        )

    def upgrade(self, command_value_object: tuple):
        polling = not command_value_object.no_wait
        return self._arm_client.upgrade_dc(
            command_value_object.resource_group,
            command_value_object.name,
            command_value_object.target,
            command_value_object.dry_run,
            polling=polling,
        )

    def list_upgrades(self, command_value_object: tuple):
        pass

    def get_status(self, command_value_object: tuple):
        resource_group = command_value_object.resource_group
        name = command_value_object.name
        return (
            self._arm_client.list_dc(resource_group)
            if not name
            else self._arm_client.get_dc(resource_group, name)
        )

    def get_config(self, command_value_object: tuple):
        pass


# ============================================================================ #
# ============================================================================ #
# ============================================================================ #


class KubernetesManagedInstanceServiceProxy(
    BaseManagedInstanceServiceProxy, KubernetesMixin
):
    def __init__(self, az_cli):
        super(KubernetesManagedInstanceServiceProxy, self).__init__()

    def create(self, command_value_object: tuple):
        pass

    def delete(self, command_value_object: tuple):
        pass

    def update(self, command_value_object: tuple):
        pass

    def list(self, command_value_object: tuple):
        pass

    def restore(self, command_value_object: tuple):
        pass

    ############################################################################
    # non abstract / indirect only functions (below)
    ############################################################################

    def get_mirroring_certificate(self, command_value_object: tuple):
        pass

    def create_fog(self, command_value_object: tuple):
        return self.client.create_fog_mi(
            command_value_object.name,
            command_value_object.namespace or self.namespace,
        )

    def delete_fog(self, command_value_object: tuple):
        return self.client.delete_fog_mi(
            command_value_object.name,
            command_value_object.namespace or self.namespace,
        )

    def list_fog(self, command_value_object: tuple):
        pass


# ============================================================================ #
# ============================================================================ #
# ============================================================================ #


class KubernetesDataControllerServiceProxy(
    BaseDataControllerServiceProxy, KubernetesMixin
):
    def __init__(self, az_cli):
        from azext_arcdata.kubernetes_sdk.dc.client import DataControllerClient

        self._client = DataControllerClient(self.stdout, self.stderr)

        super(KubernetesDataControllerServiceProxy, self).__init__()

    def create(self, command_value_object: tuple):
        cvo = command_value_object
        config_profile = cvo.path or cvo.profile_name

        return self._client.create(
            cvo.subscription,
            cvo.namespace or self.namespace,
            cvo.name,
            cvo.resource_group,
            cvo.location,
            config_profile,
            storage_class=cvo.storage_class,
            infrastructure=cvo.infrastructure,
            labels=cvo.labels,
            annotations=cvo.annotations,
            service_annotations=cvo.service_annotations,
            service_labels=cvo.service_labels,
            storage_labels=cvo.storage_labels,
            storage_annotations=cvo.storage_annotations,
            logs_ui_public_key_file=cvo.logs_ui_public_key_file,
            logs_ui_private_key_file=cvo.logs_ui_private_key_file,
            metrics_ui_public_key_file=cvo.metrics_ui_public_key_file,
            metrics_ui_private_key_file=cvo.metrics_ui_private_key_file,
        )

    def upgrade(self, command_value_object: tuple):
        return self._client.upgrade(
            command_value_object.namespace or self.namespace,
            command_value_object.target,
            dry_run=command_value_object.dry_run,
            nowait=command_value_object.no_wait,
        )

    def update(self, cvo: tuple):
        """
        Proxy call to pass the update command to the appropriate client.
        """
        return self._client.update(
            namespace=cvo.namespace,
            maintenance_start=cvo.maintenance_start,
            maintenance_duration=cvo.maintenance_duration,
            maintenance_recurrence=cvo.maintenance_recurrence,
            maintenance_time_zone=cvo.maintenance_time_zone,
            maintenance_enabled=cvo.maintenance_enabled,
        )

    def delete(self, command_value_object: tuple):
        return self._client.delete(
            command_value_object.name,
            command_value_object.namespace or self.namespace,
            force=command_value_object.force,
        )

    def list_upgrades(self, command_value_object: tuple):
        namespace = command_value_object.namespace or self.namespace
        current_version, versions = self._client.list_upgrades(namespace)

        return current_version, versions

    def list_endpoints(self, command_value_object: tuple):
        return self._client.monitor_endpoint_list(
            command_value_object.namespace or self.namespace,
            command_value_object.endpoint_name,
        )

    def get_status(self, command_value_object: tuple):
        return self._client.get_status(
            command_value_object.namespace or self.namespace
        )

    def get_config(self, command_value_object: tuple):
        namespace = command_value_object.namespace or self.namespace
        return self._client.get_config(namespace)

    ############################################################################
    # non abstract / indirect only functions (below)
    ############################################################################

    def export(self, namespace, export_type, path):
        self._client.export(namespace, export_type, path)

    def copy_logs(
        self,
        namespace,
        target_folder=None,
        pod=None,
        container=None,
        resource_kind=None,
        resource_name=None,
        timeout=0,
        skip_compress=False,
        exclude_dumps=False,
        exclude_system_logs=False,
    ):
        """
        Copy Logs commands - requires kube config
        """

        namespace = namespace or self.namespace

        copy_debug_logs(
            namespace,
            target_folder,
            pod,
            container,
            resource_kind,
            resource_name,
            timeout,
            skip_compress,
            exclude_dumps,
            exclude_system_logs,
        )

    def capture_debug_dump(
        self, namespace, container="controller", target_folder="./output/dump"
    ):
        """
        Trigger dump for given container and copy out the dump file to given
        output folder
        """
        # The following error is misleading. All the framework,
        # functions,
        # etc. to perform dump are in place and were working at the
        # time I
        # wrote this comment--except they are not adjusted to the new
        #  non-root
        # world, where CAP_SYS_PTRACE needs to be enabled in order to
        #  get a
        # core dump. So the shell script that gets called in the
        # controller
        # pod does nothing useful.
        #
        # Therefore, disabling the dump call until we can figure out
        # how we want to handle this. -safeitle, 07/21/2021
        #
        raise NotImplementedError(
            "'az arcdata dc debug dump' currently not "
            "implemented in this release. "
        )

        # -- Check Kubectl Context --
        namespace = namespace or self.namespace
        take_dump(namespace, container, target_folder)


# ============================================================================ #
# ============================================================================ #
# ============================================================================ #


@add_metaclass(ABCMeta)
class BasePostgresServiceProxy(BaseServiceProxy):
    def __init__(self):
        super(BasePostgresServiceProxy, self).__init__("pg")


class ArmPostgresServiceProxy(BasePostgresServiceProxy):
    def __init__(self, az_cli):
        super(ArmPostgresServiceProxy, self).__init__()


class KubernetesPostgresServiceProxy(BasePostgresServiceProxy, KubernetesMixin):
    def __init__(self, az_cli):
        super(KubernetesPostgresServiceProxy, self).__init__()


# ============================================================================ #
# ============================================================================ #
# ============================================================================ #


@add_metaclass(ABCMeta)
class BaseActiveDirectoryConnectorServiceProxy(BaseServiceProxy):
    def __init__(self):
        super(BaseActiveDirectoryConnectorServiceProxy, self).__init__(
            "ad_connector"
        )

    @abstractmethod
    def create(self, cvo: tuple):
        pass

    @abstractmethod
    def update(self, cvo: tuple):
        pass

    @abstractmethod
    def show(self, cvo: tuple):
        pass

    @abstractmethod
    def delete(self, cvo: tuple):
        pass


class KubernetesActiveDirectoryConnectorServiceProxy(
    BaseActiveDirectoryConnectorServiceProxy, KubernetesMixin
):
    def __init__(self, az_cli):
        from azext_arcdata.kubernetes_sdk.ad_connector.client import (
            ActiveDirectoryConnectorClient,
        )

        self._client = ActiveDirectoryConnectorClient(self.stdout, self.stderr)
        super(KubernetesActiveDirectoryConnectorServiceProxy, self).__init__()

    def create(self, cvo: tuple):
        """
        Proxy call to pass the create command to the appropriate client.
        """
        return self._client.create(
            name=cvo.name,
            namespace=cvo.namespace or self.namespace,
            realm=cvo.realm,
            nameserver_addresses=cvo.nameserver_addresses,
            account_provisioning=cvo.account_provisioning,
            primary_domain_controller=cvo.primary_domain_controller,
            secondary_domain_controllers=cvo.secondary_domain_controllers,
            netbios_domain_name=cvo.netbios_domain_name,
            dns_domain_name=cvo.dns_domain_name,
            num_dns_replicas=cvo.num_dns_replicas,
            prefer_k8s_dns=cvo.prefer_k8s_dns,
            ou_distinguished_name=cvo.ou_distinguished_name,
            domain_service_account_secret=cvo.domain_service_account_secret,
        )

    def update(self, cvo: tuple):
        """
        Proxy call to pass the update command to the appropriate client.
        """
        return self._client.update(
            name=cvo.name,
            namespace=cvo.namespace or self.namespace,
            nameserver_addresses=cvo.nameserver_addresses,
            primary_domain_controller=cvo.primary_domain_controller,
            secondary_domain_controllers=cvo.secondary_domain_controllers,
            num_dns_replicas=cvo.num_dns_replicas,
            prefer_k8s_dns=cvo.prefer_k8s_dns,
            domain_service_account_secret=cvo.domain_service_account_secret,
        )

    def show(self, cvo: tuple):
        return self._client.show(cvo.name, cvo.namespace or self.namespace)

    def delete(self, cvo: tuple):
        return self._client.delete(cvo.name, cvo.namespace or self.namespace)


class ArmActiveDirectoryConnectorServiceProxy(
    BaseActiveDirectoryConnectorServiceProxy, ArmMixin
):
    def __init__(self, az_cli):
        super(ArmActiveDirectoryConnectorServiceProxy, self).__init__()
        self._arm_client = self.acquire_arm_client(az_cli)

    def create(self, cvo: tuple):
        return self._arm_client.create_ad_connector(
            name=cvo.name,
            realm=cvo.realm,
            nameserver_addresses=cvo.nameserver_addresses,
            account_provisioning=cvo.account_provisioning,
            primary_domain_controller=cvo.primary_domain_controller,
            secondary_domain_controllers=cvo.secondary_domain_controllers,
            netbios_domain_name=cvo.netbios_domain_name,
            dns_domain_name=cvo.dns_domain_name,
            num_dns_replicas=cvo.num_dns_replicas,
            prefer_k8s_dns=cvo.prefer_k8s_dns,
            ou_distinguished_name=cvo.ou_distinguished_name,
            data_controller_name=cvo.data_controller_name,
            resource_group=cvo.resource_group,
        )

    def update(self, cvo: tuple):
        return self._arm_client.update_ad_connector(
            name=cvo.name,
            nameserver_addresses=cvo.nameserver_addresses,
            primary_domain_controller=cvo.primary_domain_controller,
            secondary_domain_controllers=cvo.secondary_domain_controllers,
            num_dns_replicas=cvo.num_dns_replicas,
            prefer_k8s_dns=cvo.prefer_k8s_dns,
            data_controller_name=cvo.data_controller_name,
            resource_group=cvo.resource_group,
        )

    def show(self, cvo: tuple):
        return self._arm_client.get_ad_connector(
            name=cvo.name,
            data_controller_name=cvo.data_controller_name,
            resource_group=cvo.resource_group,
        )

    def delete(self, cvo: tuple):
        return self._arm_client.delete_ad_connector(
            name=cvo.name,
            data_controller_name=cvo.data_controller_name,
            resource_group=cvo.resource_group,
        )
