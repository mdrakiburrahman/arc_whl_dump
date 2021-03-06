# ------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# ------------------------------------------------------------------------------

from azext_arcdata.core.constants import (
    CLI_ARG_GROUP_AD_TEXT,
    USE_K8S_TEXT,
    CLI_ARG_GROUP_DIRECT_TEXT,
    CLI_ARG_GROUP_INDIRECT_TEXT,
)
from azext_arcdata.sqlmi.constants import (
    SQLMI_LICENSE_TYPE_ALLOWED_VALUES_MSG_CREATE,
    SQLMI_LICENSE_TYPE_ALLOWED_VALUES_MSG,
    SQLMI_TIER_ALLOWED_VALUES_MSG_CREATE,
    DAG_ROLES_ALLOWED_VALUES_MSG_CREATE,
    DAG_ROLES_ALLOWED_VALUES_MSG_UPDATE,
)


def load_arguments(self, _):
    from knack.arguments import ArgumentsContext

    with ArgumentsContext(self, "sql mi-arc create") as c:
        c.argument(
            "path",
            options_list=["--path"],
            help="The path to the azext_arcdata file for the SQL managed "
            "instance json file.",
        )
        c.argument(
            "name",
            options_list=["--name", "-n"],
            help="The name of the SQL managed instance.",
        )
        c.argument(
            "dev",
            options_list=["--dev"],
            action="store_true",
            help="If this is specified, then it is considered a dev instance "
            "and will not be billed for.",
        )
        c.argument(
            "replicas",
            options_list=["--replicas"],
            help="This option specifies the number of SQL Managed Instance "
            "replicas that will be deployed in your Kubernetes cluster "
            "for high availability purpose. Allowed values are '3', '2', "
            "'1' with default of '1'.",
        )
        c.argument(
            "readable_secondaries",
            options_list=["--readable-secondaries"],
            help="Number of replicas to be made readable. Applies only to "
            "Business Critical tier.  Value must be between 0 and the "
            "number of replicas minus 1.",
        )
        c.argument(
            "cores_limit",
            options_list=["--cores-limit", "-c"],
            help="The cores limit of the managed instance as an integer.",
        )
        c.argument(
            "cores_request",
            options_list=["--cores-request"],
            help="The request for cores of the managed instance as an "
            "integer.",
        )
        c.argument(
            "memory_limit",
            options_list=["--memory-limit", "-m"],
            help="The limit of the capacity of the managed instance as an "
            "integer number followed by Gi (gigabytes). Example: 4Gi",
        )
        c.argument(
            "memory_request",
            options_list=["--memory-request"],
            help="The request for the capacity of the managed instance as an "
            "integer number followed by Gi (gigabytes). Example: 4Gi",
        )
        c.argument(
            "storage_class_data",
            options_list=["--storage-class-data", "-d"],
            help="The storage class to be used for data files (.mdf, .ndf). "
            "If no value is specified, then no storage class will be "
            "specified, which will result in Kubernetes using the "
            "default storage class.",
        )
        c.argument(
            "storage_class_datalogs",
            options_list=["--storage-class-datalogs"],
            help="The storage class to be used for database logs (.ldf). If "
            "no value is specified, then no storage class will be "
            "specified, which will result in Kubernetes using the "
            "default storage class.",
        )
        c.argument(
            "storage_class_logs",
            options_list=["--storage-class-logs"],
            help="The storage class to be used for logs (/var/log). If no "
            "value is specified, then no storage class will be "
            "specified, which will result in Kubernetes using the "
            "default storage class.",
        )
        c.argument(
            "storage_class_backups",
            options_list=["--storage-class-backups"],
            help="A ReadWriteMany (RWX) capable storage class to be used for "
            "backups (/var/opt/mssql/backups). If no value is specified, "
            "the default storage class will be used.",
        )
        c.argument(
            "volume_size_data",
            options_list=["--volume-size-data"],
            help="The size of the storage volume to be used for data as a "
            "positive number followed by Ki (kilobytes),"
            " Mi (megabytes), or Gi (gigabytes).",
        )
        c.argument(
            "volume_size_datalogs",
            options_list=["--volume-size-datalogs"],
            help="The size of the storage volume to be used for data logs as "
            "a positive number followed by Ki (kilobytes), "
            "Mi (megabytes), or Gi (gigabytes).",
        )
        c.argument(
            "volume_size_logs",
            options_list=["--volume-size-logs"],
            help="The size of the storage volume to be used for logs as a "
            "positive number followed by Ki (kilobytes), "
            "Mi (megabytes), or Gi (gigabytes).",
        )
        c.argument(
            "volume_size_backups",
            options_list=["--volume-size-backups"],
            help="The size of the storage volume to be used for backups as "
            "a positive number followed by Ki (kilobytes), "
            "Mi (megabytes), or Gi (gigabytes).",
        )
        c.argument(
            "license_type",
            options_list=["--license-type", "-l"],
            help="The license type to apply for this managed instance "
            "{}.".format(SQLMI_LICENSE_TYPE_ALLOWED_VALUES_MSG_CREATE),
        )
        c.argument(
            "tier",
            options_list=["--tier", "-t"],
            help="The pricing tier for the instance. {}".format(
                SQLMI_TIER_ALLOWED_VALUES_MSG_CREATE
            ),
        )
        # -- indirect --
        c.argument(
            "labels",
            options_list=["--labels"],
            arg_group=CLI_ARG_GROUP_INDIRECT_TEXT,
            help="Comma-separated list of labels of the SQL managed instance.",
        )
        c.argument(
            "annotations",
            options_list=["--annotations"],
            arg_group=CLI_ARG_GROUP_INDIRECT_TEXT,
            help="Comma-separated list of annotations of the SQL "
            "managed instance.",
        )
        c.argument(
            "service_labels",
            options_list=["--service-labels"],
            arg_group=CLI_ARG_GROUP_INDIRECT_TEXT,
            help="Comma-separated list of labels to apply to all external "
            "services.",
        )
        c.argument(
            "service_annotations",
            options_list=["--service-annotations"],
            arg_group=CLI_ARG_GROUP_INDIRECT_TEXT,
            help="Comma-separated list of annotations to apply to all "
            "external services.",
        )
        c.argument(
            "storage_labels",
            options_list=["--storage-labels"],
            arg_group=CLI_ARG_GROUP_INDIRECT_TEXT,
            help="Comma-separated list of labels to apply to all PVCs.",
        )
        c.argument(
            "storage_annotations",
            options_list=["--storage-annotations"],
            arg_group=CLI_ARG_GROUP_INDIRECT_TEXT,
            help="Comma-separated list of annotations to apply to all PVCs.",
        )
        c.argument(
            "noexternal_endpoint",
            options_list=["--no-external-endpoint"],
            arg_group=CLI_ARG_GROUP_INDIRECT_TEXT,
            action="store_true",
            help="If specified, no external service will be created. "
            "Otherwise, an external service will be created using the "
            "same service type as the data controller.",
        )
        c.argument(
            "certificate_public_key_file",
            options_list=["--cert-public-key-file"],
            arg_group=CLI_ARG_GROUP_INDIRECT_TEXT,
            help="Path to the file containing a PEM formatted certificate "
            "public key to be used for SQL Server.",
        )
        c.argument(
            "certificate_private_key_file",
            options_list=["--cert-private-key-file"],
            arg_group=CLI_ARG_GROUP_INDIRECT_TEXT,
            help="Path to the file containing a PEM formatted certificate "
            "private key to be used for SQL Server.",
        )
        c.argument(
            "service_certificate_secret",
            options_list=["--service-cert-secret"],
            arg_group=CLI_ARG_GROUP_INDIRECT_TEXT,
            help="Name of the Kubernetes secret to generate that hosts or "
            "will host SQL service certificate.",
        )
        c.argument(
            "admin_login_secret",
            options_list=["--admin-login-secret"],
            arg_group=CLI_ARG_GROUP_INDIRECT_TEXT,
            help="Name of the Kubernetes secret to generate that hosts or "
            "will host user admin login account credential.",
        )
        c.argument(
            "collation",
            options_list=["--collation"],
            arg_group=CLI_ARG_GROUP_INDIRECT_TEXT,
            help="The SQL Server collation for the instance.",
        )
        c.argument(
            "language",
            options_list=["--language"],
            arg_group=CLI_ARG_GROUP_INDIRECT_TEXT,
            help="The SQL Server locale to any supported language identifier "
            "(LCID) for the instance.",
        )
        c.argument(
            "agent_enabled",
            options_list=["--agent-enabled"],
            arg_group=CLI_ARG_GROUP_INDIRECT_TEXT,
            help="Enable SQL Server agent for the instance. Default is "
            "disabled. Allowed values are 'true' or 'false'.",
        )
        c.argument(
            "trace_flags",
            options_list=["--trace-flags"],
            arg_group=CLI_ARG_GROUP_INDIRECT_TEXT,
            help="Comma separated list of traceflags. No flags by default.",
        )
        c.argument(
            "time_zone",
            options_list=["--time-zone"],
            arg_group=CLI_ARG_GROUP_INDIRECT_TEXT,
            help="The SQL Server time zone for the instance.",
        )
        c.argument(
            "retention_days",
            options_list=["--retention-days"],
            arg_group=CLI_ARG_GROUP_INDIRECT_TEXT,
            help="Backup retention period, specified in days. "
            "Allowed values are 0 to 35. Default is 7. Setting "
            "the retention period to 0 will turn off automatic "
            "backups for all the databases on the SQL managed "
            "instance and any prior backups will be deleted.",
        )
        c.argument(
            "namespace",
            options_list=["--k8s-namespace", "-k"],
            arg_group=CLI_ARG_GROUP_INDIRECT_TEXT,
            help="Namespace where the SQL managed instance is to be deployed. "
            "If no namespace is specified, then the namespace defined "
            "in the kubeconfig will be used.",
        )
        c.argument(
            "use_k8s",
            options_list=["--use-k8s"],
            arg_group=CLI_ARG_GROUP_INDIRECT_TEXT,
            action="store_true",
            help="Create SQL managed instance using local Kubernetes APIs.",
        )
        # -- direct --
        c.argument(
            "location",
            options_list=["--location"],
            arg_group=CLI_ARG_GROUP_DIRECT_TEXT,
            help="The Azure location in which the sqlmi metadata "
            "will be stored (e.g. eastus).",
        )
        c.argument(
            "custom_location",
            options_list=["--custom-location"],
            arg_group=CLI_ARG_GROUP_DIRECT_TEXT,
            help="The custom location for this instance.",
        )
        c.argument(
            "resource_group",
            options_list=["--resource-group", "-g"],
            arg_group=CLI_ARG_GROUP_DIRECT_TEXT,
            help="The Azure resource group in which the sqlmi "
            "resource should be added.",
        )
        # -- Active Directory --
        c.argument(
            "ad_connector_name",
            options_list=["--ad-connector-name"],
            arg_group=CLI_ARG_GROUP_AD_TEXT,
            help="The name of the Active Directory Connector. This parameter indicates an intent to deploy with AD support.",
        )
        c.argument(
            "ad_account_name",
            options_list=["--ad-account-name"],
            arg_group=CLI_ARG_GROUP_AD_TEXT,
            help="The Active Directory account name for this Arc-enabled SQL Managed Instance. This account needs to be created prior to the deployment of this instance.",
        )
        c.argument(
            "keytab_secret",
            options_list=["--keytab-secret"],
            arg_group=CLI_ARG_GROUP_AD_TEXT,
            help="The name of the Kubernetes secret that contains the keytab file for this Arc-enabled SQL Managed Instance.",
        )
        c.argument(
            "primary_dns_name",
            options_list=["--primary-dns-name"],
            arg_group=CLI_ARG_GROUP_AD_TEXT,
            help="The primary service DNS name exposed to the end-users to connect to this Arc-enabled SQL Managed Instance (e.g. sqlinstancename.contoso.com).",
        )
        c.argument(
            "primary_port_number",
            options_list=["--primary-port-number"],
            arg_group=CLI_ARG_GROUP_AD_TEXT,
            help="The port number on which the primary DNS service is exposed to the end-users (e.g. 31433).",
        )
        # c.argument(
        #     "secondary_dns_name",
        #     options_list=["--secondary-dns-name"],
        #     arg_group=CLI_ARG_GROUP_AD_TEXT,
        #     help="The secondary service DNS name exposed to the end-users to connect to this Arc-enabled SQL Managed Instance (e.g. sqlinstancename2.contoso.com).",
        # )
        # c.argument(
        #     "secondary_port_number",
        #     options_list=["--secondary-port-number"],
        #     arg_group=CLI_ARG_GROUP_AD_TEXT,
        #     help="The port number on which the secondary DNS service is exposed to the end-users (e.g. 31444).",
        # )

    with ArgumentsContext(self, "sql mi-arc upgrade") as c:
        c.argument(
            "path",
            options_list=["--path"],
            help="The path to the azext_arcdata file for the SQL managed "
            "instance json file.",
        )
        c.argument(
            "name",
            options_list=["--name", "-n"],
            help="The name of the SQL managed instance.",
        )
        c.argument(
            "replicas",
            options_list=["--replicas"],
            help="This option specifies the number of SQL Managed Instance "
            "replicas that will be updated in your Kubernetes cluster. "
            "Allowed values for General Purpose: 1, Business Critical: 1, 2, 3.",
        )
        c.argument(
            "field_filter",
            options_list=["--field-filter", "-f"],
            help="Filter to select instances to upgrade based on resource "
            "properties.",
        )
        c.argument(
            "label_filter",
            options_list=["--label-filter", "-l"],
            help="Filter to select instance to upgrade based on labels.",
        )
        c.argument(
            "dry_run",
            options_list=["--dry-run", "-d"],
            action="store_true",
            help="Indicates which instance would be upgraded but does not "
            "actually upgrade the instances.",
        )
        c.argument(
            "desired_version",
            options_list=[
                "--desired-version",
                "-v",
                c.deprecate(
                    target="--target", redirect="--desired-version", hide=False
                ),
            ],
            help="Desired version to upgrade to. Optional if no version "
            "specified, the data controller version will be used.",
        )
        c.argument(
            "force",
            options_list=["--force"],
            help="Overrides all policies that may be applied to the instance, "
            "and attempts the upgrade.",
            action="store_true",
        )
        c.argument(
            "nowait",
            options_list=["--no-wait"],
            action="store_true",
            help="If given, the command will not wait for the instance to be "
            "in a ready state before returning.",
        )
        # -- indirect --
        c.argument(
            "namespace",
            options_list=["--k8s-namespace", "-k"],
            arg_group=CLI_ARG_GROUP_INDIRECT_TEXT,
            help="Namespace where the SQL managed instance is to be deployed. "
            "If no namespace is specified, then the namespace defined "
            "in the kubeconfig will be used.",
        )
        c.argument(
            "use_k8s",
            options_list=["--use-k8s"],
            arg_group=CLI_ARG_GROUP_INDIRECT_TEXT,
            action="store_true",
            help="Create SQL managed instance using local Kubernetes APIs.",
        )
        # -- direct --
        c.argument(
            "resource_group",
            options_list=["--resource-group", "-g"],
            arg_group=CLI_ARG_GROUP_DIRECT_TEXT,
            help="The Azure resource group in which the sqlmi "
            "resource should be added.",
        )

    with ArgumentsContext(self, "sql mi-arc update") as c:
        c.argument(
            "path",
            options_list=["--path"],
            help="The path to the azext_arcdata file for the SQL managed "
            "instance json file.",
        )
        c.argument(
            "name",
            options_list=["--name", "-n"],
            help="The name of the SQL managed instance that is being edited. "
            "The name under which your instance is deployed cannot be "
            "changed.",
        )
        c.argument(
            "time_zone",
            options_list=["--time-zone"],
            help="The SQL Server time zone for the instance.",
        )
        c.argument(
            "cores_limit",
            options_list=["--cores-limit", "-c"],
            help="The cores limit of the managed instance as an integer.",
        )
        c.argument(
            "cores_request",
            options_list=["--cores-request"],
            help="The request for cores of the managed instance as "
            "an integer.",
        )
        c.argument(
            "memory_limit",
            options_list=["--memory-limit", "-m"],
            help="The limit of the capacity of the managed instance as an "
            "integer number followed by Gi (gigabytes). Example: 4Gi",
        )
        c.argument(
            "memory_request",
            options_list=["--memory-request"],
            help="The request for the capacity of the managed instance as an "
            "integer number followed by Gi (gigabytes). Example: 4Gi",
        )
        c.argument(
            "license_type",
            options_list=["--license-type", "-l"],
            help="The license type to apply for this managed instance "
            "{}.".format(SQLMI_LICENSE_TYPE_ALLOWED_VALUES_MSG_CREATE),
        )
        c.argument(
            "labels",
            options_list=["--labels"],
            help="Comma-separated list of labels of the SQL managed instance.",
        )
        c.argument(
            "annotations",
            options_list=["--annotations"],
            help="Comma-separated list of annotations of the SQL managed "
            "instance.",
        )
        c.argument(
            "service_labels",
            options_list=["--service-labels"],
            help="Comma-separated list of labels to apply to all external "
            "services.",
        )
        c.argument(
            "service_annotations",
            options_list=["--service-annotations"],
            help="Comma-separated list of annotations to apply to all "
            "external services.",
        )
        c.argument(
            "agent_enabled",
            options_list=["--agent-enabled"],
            help="Enable SQL Server agent for the instance. Default is "
            "disabled.",
        )
        c.argument(
            "trace_flags",
            options_list=["--trace-flags"],
            help="Comma separated list of traceflags. No flags by default.",
        )
        c.argument(
            "retention_days",
            options_list=["--retention-days"],
            help="Backup retention period, specified in days. "
            "Allowed values are 0 to 35. Default is 7. Setting "
            "the retention period to 0 will turn off automatic "
            "backups for all the databases on the SQL managed "
            "instance and any prior backups will be deleted.",
        )
        c.argument(
            "preferred_primary_replica",
            options_list=["--preferred-primary-replica"],
            help="",
        )
        c.argument(
            "replicas",
            options_list=["--replicas"],
            help="This option specifies the number of SQL Managed Instance "
            "replicas that will be deployed in your Kubernetes cluster "
            "for high availability purpose. Allowed values are '3', '2', "
            "'1' with default of '1'.",
        )
        c.argument(
            "readable_secondaries",
            options_list=["--readable-secondaries"],
            help="Number of replicas to be made readable. Applies only to "
            "Business Critical tier.  Value must be between 0 and the "
            "number of replicas minus 1.",
        )
        # -- indirect --
        c.argument(
            "namespace",
            options_list=["--k8s-namespace", "-k"],
            arg_group=CLI_ARG_GROUP_INDIRECT_TEXT,
            help="Namespace where the SQL managed instance is to be "
            "deployed. If no namespace is specified, then the namespace "
            "defined in the kubeconfig will be used.",
        )
        c.argument(
            "use_k8s",
            options_list=["--use-k8s"],
            arg_group=CLI_ARG_GROUP_INDIRECT_TEXT,
            action="store_true",
            help="Create SQL managed instance using local Kubernetes APIs.",
        )
        c.argument(
            "certificate_public_key_file",
            options_list=["--cert-public-key-file"],
            arg_group=CLI_ARG_GROUP_INDIRECT_TEXT,
            help="Path to the file containing a PEM formatted certificate "
            "public key to be used for SQL Server.",
        )
        c.argument(
            "certificate_private_key_file",
            options_list=["--cert-private-key-file"],
            arg_group=CLI_ARG_GROUP_INDIRECT_TEXT,
            help="Path to the file containing a PEM formatted certificate "
            "private key to be used for SQL Server.",
        )
        c.argument(
            "service_certificate_secret",
            options_list=["--service-cert-secret"],
            arg_group=CLI_ARG_GROUP_INDIRECT_TEXT,
            help="Name of the Kubernetes secret to generate that hosts or "
            "will host SQL service certificate.",
        )
        c.argument(
            "preferred_primary_replica",
            options_list=["--preferred-primary-replica"],
            arg_group=CLI_ARG_GROUP_INDIRECT_TEXT,
            help="The preferred primary replica to be updated.",
        )
        # -- direct --
        c.argument(
            "resource_group",
            options_list=["--resource-group", "-g"],
            arg_group=CLI_ARG_GROUP_DIRECT_TEXT,
            help="The Azure resource group in which the sqlmi "
            "resource should be updated.",
        )
        # -- Active Directory --
        c.argument(
            "keytab_secret",
            options_list=["--keytab-secret"],
            arg_group=CLI_ARG_GROUP_AD_TEXT,
            help="The name of the Kubernetes secret that contains the keytab file for this Arc-enabled SQL Managed Instance.",
        )

    with ArgumentsContext(self, "sql mi-arc edit") as c:
        c.argument(
            "path",
            options_list=["--path"],
            help="The path to the azext_arcdata file for the SQL managed "
            "instance json file.",
        )
        c.argument(
            "name",
            options_list=["--name", "-n"],
            help="The name of the SQL managed instance that is being edited. "
            "The name under which your instance is deployed cannot be "
            "changed.",
        )
        c.argument(
            "time_zone",
            options_list=["--time-zone"],
            help="The SQL Server time zone for the instance.",
        )
        c.argument(
            "dev",
            options_list=["--dev"],
            action="store_true",
            help="If this is specified, then it is considered a dev instance "
            "and will not be billed for.",
        )
        c.argument(
            "cores_limit",
            options_list=["--cores-limit", "-c"],
            help="The cores limit of the managed instance as an integer.",
        )
        c.argument(
            "cores_request",
            options_list=["--cores-request"],
            help="The request for cores of the managed instance as "
            "an integer.",
        )
        c.argument(
            "memory_limit",
            options_list=["--memory-limit", "-m"],
            help="The limit of the capacity of the managed instance as an "
            "integer number followed by Gi (gigabytes). Example: 4Gi",
        )
        c.argument(
            "memory_request",
            options_list=["--memory-request"],
            help="The request for the capacity of the managed instance as an "
            "integer number followed by Gi (gigabytes). Example: 4Gi",
        )
        c.argument(
            "nowait",
            options_list=["--no-wait"],
            action="store_true",
            help="If given, the command will not wait for the instance to be "
            "in a ready state before returning.",
        )
        c.argument(
            "labels",
            options_list=["--labels"],
            help="Comma-separated list of labels of the SQL managed instance.",
        )
        c.argument(
            "license_type",
            options_list=["--license-type"],
            help="The license type to update for this managed instance "
            "{}".format(SQLMI_LICENSE_TYPE_ALLOWED_VALUES_MSG),
        )
        c.argument(
            "annotations",
            options_list=["--annotations"],
            help="Comma-separated list of annotations of the SQL managed "
            "instance.",
        )
        c.argument(
            "service_labels",
            options_list=["--service-labels"],
            help="Comma-separated list of labels to apply to all external "
            "services.",
        )
        c.argument(
            "service_annotations",
            options_list=["--service-annotations"],
            help="Comma-separated list of annotations to apply to all "
            "external services.",
        )
        c.argument(
            "agent_enabled",
            options_list=["--agent-enabled"],
            help="Enable SQL Server agent for the instance. Default is "
            "disabled.",
        )
        c.argument(
            "trace_flags",
            options_list=["--trace-flags"],
            help="Comma separated list of traceflags. No flags by default.",
        )
        c.argument(
            "retention_days",
            options_list=["--retention-days"],
            help="Backup retention period, specified in days. "
            "Allowed values are 0 to 35. Default is 7. Setting "
            "the retention period to 0 will turn off automatic "
            "backups for all the databases on the SQL managed "
            "instance and any prior backups will be deleted.",
        )
        # -- indirect --
        c.argument(
            "namespace",
            options_list=["--k8s-namespace", "-k"],
            arg_group=CLI_ARG_GROUP_INDIRECT_TEXT,
            help="Namespace where the SQL managed instance is to be "
            "deployed. If no namespace is specified, then the namespace "
            "defined in the kubeconfig will be used.",
        )
        c.argument(
            "use_k8s",
            options_list=["--use-k8s"],
            arg_group=CLI_ARG_GROUP_INDIRECT_TEXT,
            action="store_true",
            help="Create SQL managed instance using local Kubernetes APIs.",
        )
        # -- direct --
        c.argument(
            "location",
            options_list=["--location"],
            arg_group=CLI_ARG_GROUP_DIRECT_TEXT,
            help="The Azure location in which the sqlmi metadata "
            "will be stored (e.g. eastus).",
        )
        c.argument(
            "custom_location",
            options_list=["--custom-location"],
            arg_group=CLI_ARG_GROUP_DIRECT_TEXT,
            help="[Required] The custom location for this instance.",
        )
        c.argument(
            "resource_group",
            options_list=["--resource-group", "-g"],
            arg_group=CLI_ARG_GROUP_DIRECT_TEXT,
            help="The Azure resource group in which the sqlmi "
            "resource should be added.",
        )
        c.argument(
            "tag_name",
            options_list=["--tag-name"],
            arg_group=CLI_ARG_GROUP_DIRECT_TEXT,
            help="The tag name of the SQL managed instance.",
        )
        c.argument(
            "tag_value",
            options_list=["--tag-value"],
            arg_group=CLI_ARG_GROUP_DIRECT_TEXT,
            help="The tag value of the SQL managed instance.",
        )

    with ArgumentsContext(self, "sql mi-arc delete") as c:
        c.argument(
            "name",
            options_list=["--name", "-n"],
            help="The name of the SQL managed instance to be deleted.",
        )
        # -- indirect --
        c.argument(
            "namespace",
            options_list=["--k8s-namespace", "-k"],
            arg_group=CLI_ARG_GROUP_INDIRECT_TEXT,
            help="Namespace where the SQL managed instance is to be deployed. "
            "If no namespace is specified, then the namespace defined "
            "in the kubeconfig will be used.",
        )
        c.argument(
            "use_k8s",
            options_list=["--use-k8s"],
            arg_group=CLI_ARG_GROUP_INDIRECT_TEXT,
            action="store_true",
            help="Create SQL managed instance using local Kubernetes APIs.",
        )
        # -- direct --
        c.argument(
            "resource_group",
            options_list=["--resource-group", "-g"],
            arg_group=CLI_ARG_GROUP_DIRECT_TEXT,
            help="The Azure resource group in which the sqlmi "
            "resource should be deleted.",
        )

    with ArgumentsContext(self, "sql mi-arc show") as c:
        c.argument(
            "name",
            options_list=["--name", "-n"],
            help="The name of the SQL managed instance to be shown.",
        )
        c.argument(
            "path",
            options_list=["--path", "-p"],
            help="A path where the full specification for the SQL managed "
            "instance should be written. If omitted, the specification "
            "will be written to standard output.",
        )
        # -- indirect --
        c.argument(
            "namespace",
            options_list=["--k8s-namespace", "-k"],
            arg_group=CLI_ARG_GROUP_INDIRECT_TEXT,
            help="Namespace where the SQL managed instance is to be deployed. "
            "If no namespace is specified, then the namespace defined "
            "in the kubeconfig will be used.",
        )
        c.argument(
            "use_k8s",
            options_list=["--use-k8s"],
            arg_group=CLI_ARG_GROUP_INDIRECT_TEXT,
            action="store_true",
            help="Create SQL managed instance using local Kubernetes APIs.",
        )
        # -- direct --
        c.argument(
            "resource_group",
            options_list=["--resource-group", "-g"],
            arg_group=CLI_ARG_GROUP_DIRECT_TEXT,
            help="The Azure resource group in which the sqlmi "
            "resource should be shown.",
        )

    with ArgumentsContext(self, "sql mi-arc list") as c:
        # -- indirect --
        c.argument(
            "namespace",
            options_list=["--k8s-namespace", "-k"],
            arg_group=CLI_ARG_GROUP_INDIRECT_TEXT,
            help="Namespace where the SQL managed instance is to be deployed. "
            "If no namespace is specified, then the namespace defined "
            "in the kubeconfig will be used.",
        )
        c.argument(
            "use_k8s",
            options_list=["--use-k8s"],
            arg_group=CLI_ARG_GROUP_INDIRECT_TEXT,
            action="store_true",
            help="Create SQL managed instance using local Kubernetes APIs.",
        )
        # -- direct --
        c.argument(
            "resource_group",
            options_list=["--resource-group", "-g"],
            arg_group=CLI_ARG_GROUP_DIRECT_TEXT,
            help="The Azure resource group in which the sqlmi "
            "resource should be listed.",
        )

    with ArgumentsContext(self, "sql mi-arc endpoint list") as c:
        c.argument(
            "name",
            options_list=["--name", "-n"],
            help="The name of the SQL instance to be shown. If omitted, all"
            " endpoints for all instances will be shown.",
        )
        c.argument(
            "namespace",
            options_list=["--k8s-namespace", "-k"],
            help="Namespace where the SQL managed instances exist. "
            "If no namespace is specified, then the namespace defined "
            "in the kubeconfig will be used.",
        )
        c.argument(
            "use_k8s",
            options_list=["--use-k8s"],
            # deprecate_info=c.deprecate(hide=True),
            action="store_true",
            help=USE_K8S_TEXT,
        )

    with ArgumentsContext(self, "sql mi-arc config init") as c:
        c.argument(
            "path",
            options_list=["--path", "-p"],
            help="A path where the CRD and specification for the SQL managed "
            "instance should be written.",
        )

    with ArgumentsContext(self, "sql mi-arc config add") as c:
        c.argument(
            "path",
            options_list=["--path", "-p"],
            help="Path to the custom resource specification, i.e. "
            "custom/spec.json",
        )

        ex1 = '`key=\'{"kind":"cluster","name":"test-cluster"}\'`'
        ex2 = r"`key1=\"key2\=val2\,key3\=val3\"`"
        c.argument(
            "json_values",
            options_list=["--json-values", "-j"],
            help="A key value pair list of json paths to values: "
            "`key1.subkey1=value1,key2.subkey2=value2`. "
            "You may provide inline json values such as: "
            "{0} "
            "or provide a file path, such as `key=./values.json`. "
            "The add command does NOT support conditionals. If the inline "
            "value you are providing is a key value pair itself with `=` "
            "and `,`  please escape those characters. For example: "
            "{1}. Please see "
            "http://jsonpatch.com/ for examples of how your path should "
            "look. If you would like to access an array, you must do so "
            "by indicating the index, such as `key.0=value`.".format(ex1, ex2),
        )

    with ArgumentsContext(self, "sql mi-arc config replace") as c:
        c.argument(
            "path",
            options_list=["--path", "-p"],
            help="Path to the custom resource specification, i.e. "
            "`custom/spec.json`",
        )

        ex1 = '`key={"kind":"cluster","name":"test-cluster"}`'
        ex2 = r"`key1=\"key2\=val2\,key3\=val3\"`"

        c.argument(
            "json_values",
            options_list=["--json-values", "-j"],
            help="A key value pair list of json paths to values: "
            "`key1.subkey1=value1,key2.subkey2=value2`. You may provide "
            "inline json values such as: {0} or provide a file path, such "
            "as `key=./values.json`. The replace command supports "
            "conditionals through the jsonpath library. To use this, "
            "start your path with a $. This will allow you to do a "
            "conditional such as "
            '`-j $.key1.key2[?(@.key3=="someValue"].key4=value`. If the '
            "inline value you are providing is a key value pair itself "
            "with `=` and `,` please escape those characters. For example, "
            "{1}. You may see examples below. For additional help, "
            "see: https://jsonpath.com/".format(ex1, ex2),
        )

    with ArgumentsContext(self, "sql mi-arc config remove") as c:
        c.argument(
            "path",
            options_list=["--path", "-p"],
            help="Path to the custom resource specification, i.e. "
            "`custom/spec.json`.",
        )

        c.argument(
            "json_path",
            options_list=["--json-path", "-j"],
            help="A list of json paths based on the jsonpatch library that "
            "indicates which values you would like removed, "
            "such as: `key1.subkey1,key2.subkey2`. The remove command "
            "does NOT support conditionals. Please see "
            "http://jsonpatch.com/ for examples of how your path should "
            "look.  If you would like to access an array, you must do so "
            "by indicating the index, such as `key.0=value`.",
        )

    with ArgumentsContext(self, "sql mi-arc config patch") as c:
        c.argument(
            "path",
            options_list=["--path", "-p"],
            help="Path to the custom resource specification, i.e. "
            "`custom/spec.json`",
        )
        c.argument(
            "patch_file",
            options_list=["--patch-file"],
            help="Path to a patch json file that is based off the jsonpatch "
            "library: http://jsonpatch.com/. You must start your patch "
            "json file with a key called `patch`, whose value is an "
            "array of patch operations you intend to make. "
            "For the path of a patch operation, you may use dot "
            "notation, such as `key1.key2` for most operations. If you "
            "would like to do a replace operation, and you are "
            "replacing a value in an array that requires a conditional, "
            "please use the jsonpath notation by beginning your path "
            "with a $. This will allow you to do a conditional such "
            'as `$.key1.key2[?(@.key3=="someValue"].key4`.'
            "See the "
            "examples below. For additional help with conditionals, "
            "see: https://jsonpath.com/.",
        )

    with ArgumentsContext(self, "sql instance-failover-group-arc create") as c:
        c.argument(
            "name",
            options_list=["--name", "-n"],
            help="The name of the failover group resource.",
        )
        c.argument(
            "shared_name",
            options_list=["--shared-name"],
            help="The shared name of the failover group for this SQL "
            "managed instance. Both Managed Instance and its partner have to use the same "
            "shared name.",
        )
        c.argument(
            "mi",
            options_list=["--mi"],
            help="The name of the local SQL managed instance.",
        )
        c.argument(
            "role",
            options_list=["--role"],
            help="The requested role of the failover group. "
            "{}".format(DAG_ROLES_ALLOWED_VALUES_MSG_CREATE),
        )
        c.argument(
            "partner_mi",
            options_list=["--partner-mi"],
            help="The name of the partner SQL managed instance or remote SQL "
            "instance",
        )
        c.argument(
            "partner_mirroring_url",
            options_list=["--partner-mirroring-url", "-u"],
            help="The mirroring endpoint URL of the partner SQL managed "
            "instance.",
        )
        c.argument(
            "partner_mirroring_cert_file",
            options_list=["--partner-mirroring-cert-file", "-f"],
            help="The filename of mirroring endpoint public certificate for "
            "the partner SQL managed instance or availability group on remote SQL "
            "instance. Only PEM format is supported.",
        )
        # -- indirect --
        c.argument(
            "namespace",
            options_list=["--k8s-namespace", "-k"],
            arg_group=CLI_ARG_GROUP_INDIRECT_TEXT,
            help="Namespace where the failover group is to be deployed. "
            "If no namespace is specified, then the namespace defined "
            "in the kubeconfig will be used.",
        )
        c.argument(
            "use_k8s",
            options_list=["--use-k8s"],
            arg_group=CLI_ARG_GROUP_INDIRECT_TEXT,
            action="store_true",
            help="Create SQL managed instance using local Kubernetes APIs.",
        )

    with ArgumentsContext(self, "sql instance-failover-group-arc update") as c:
        c.argument(
            "name",
            options_list=["--name", "-n"],
            help="The name of the failover group resource.",
        )
        c.argument(
            "role",
            options_list=["--role"],
            help="The requested role change of failover group "
            "resource. "
            "{}".format(DAG_ROLES_ALLOWED_VALUES_MSG_UPDATE),
        )
        c.argument(
            "namespace",
            options_list=["--k8s-namespace", "-k"],
            help="Namespace where the failover group exists. "
            "If no namespace is specified, then the namespace defined "
            "in the kubeconfig will be used.",
        )
        c.argument(
            "use_k8s",
            options_list=["--use-k8s"],
            action="store_true",
            help=USE_K8S_TEXT,
        )

    with ArgumentsContext(self, "sql instance-failover-group-arc delete") as c:
        c.argument(
            "name",
            options_list=["--name"],
            help="The name of the failover group resource.",
        )
        # -- indirect --
        c.argument(
            "namespace",
            options_list=["--k8s-namespace", "-k"],
            arg_group=CLI_ARG_GROUP_INDIRECT_TEXT,
            help="Namespace where the failover group is deployed. "
            "If no namespace is specified, then the namespace defined "
            "in the kubeconfig will be used.",
        )
        c.argument(
            "use_k8s",
            options_list=["--use-k8s"],
            arg_group=CLI_ARG_GROUP_INDIRECT_TEXT,
            action="store_true",
            help="Create SQL managed instance using local Kubernetes APIs.",
        )

    with ArgumentsContext(self, "sql instance-failover-group-arc show") as c:
        c.argument(
            "name",
            options_list=["--name"],
            help="The name of the failover group resource.",
        )
        # -- indirect --
        c.argument(
            "namespace",
            options_list=["--k8s-namespace", "-k"],
            arg_group=CLI_ARG_GROUP_INDIRECT_TEXT,
            help="Namespace where the failover group is to be deployed. "
            "If no namespace is specified, then the namespace defined "
            "in the kubeconfig will be used.",
        )
        c.argument(
            "use_k8s",
            options_list=["--use-k8s"],
            arg_group=CLI_ARG_GROUP_INDIRECT_TEXT,
            action="store_true",
            help="Create SQL managed instance using local Kubernetes APIs.",
        )

    with ArgumentsContext(self, "sql mi-arc get-mirroring-cert") as c:
        c.argument(
            "name",
            options_list=["--name", "-n"],
            help="The name of the SQL managed instance.",
        )
        c.argument(
            "cert_file",
            options_list=["--cert-file"],
            help="The local filename to store the retrieved certificate in "
            "PEM format.",
        )
        # -- indirect --
        c.argument(
            "namespace",
            options_list=["--k8s-namespace", "-k"],
            arg_group=CLI_ARG_GROUP_INDIRECT_TEXT,
            help="Namespace where the SQL managed instance is to be deployed. "
            "If no namespace is specified, then the namespace defined "
            "in the kubeconfig will be used.",
        )
        c.argument(
            "use_k8s",
            options_list=["--use-k8s"],
            arg_group=CLI_ARG_GROUP_INDIRECT_TEXT,
            # deprecate_info=c.deprecate(hide=True),
            action="store_true",
            help="Create SQL managed instance using local Kubernetes APIs.",
        )
