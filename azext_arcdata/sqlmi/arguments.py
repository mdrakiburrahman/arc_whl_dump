# ------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# ------------------------------------------------------------------------------

from azext_arcdata.sqlmi.constants import (
    SQLMI_LICENSE_TYPE_ALLOWED_VALUES_MSG_CREATE,
    SQLMI_TIER_ALLOWED_VALUES_MSG_CREATE,
)
from azext_arcdata.core.constants import USE_K8S_TEXT


def load_arguments(self, _):
    from knack.arguments import ArgumentsContext

    with ArgumentsContext(self, "sql mi-arc create") as arg_context:
        arg_context.argument(
            "path",
            options_list=["--path"],
            help="The path to the azext_arcdata file for the SQL managed instance json file.",
        )
        arg_context.argument(
            "name",
            options_list=["--name", "-n"],
            help="The name of the SQL managed instance.",
        )
        arg_context.argument(
            "namespace",
            options_list=["--k8s-namespace", "-k"],
            help="Namespace where the SQL managed instance is to be deployed. "
            "If no namespace is specified, then the namespace defined "
            "in the kubeconfig will be used.",
        )
        arg_context.argument(
            "dev",
            options_list=["--dev"],
            action="store_true",
            help="If this is specified, then it is considered a dev instance and will not be billed for.",
        )
        arg_context.argument(
            "replicas",
            options_list=["--replicas"],
            help="This option specifies the number of SQL Managed Instance replicas that will be deployed in your Kubernetes cluster for high availability purpose. Allowed values are '3' or '1' with default of '1'.",
        )
        arg_context.argument(
            "cores_limit",
            options_list=["--cores-limit", "-c"],
            help="The cores limit of the managed instance as an integer.",
        )
        arg_context.argument(
            "cores_request",
            options_list=["--cores-request"],
            help="The request for cores of the managed instance as an integer.",
        )
        arg_context.argument(
            "memory_limit",
            options_list=["--memory-limit", "-m"],
            help="The limit of the capacity of the managed instance as an integer number followed by Gi (gigabytes). Example: 4Gi",
        )
        arg_context.argument(
            "memory_request",
            options_list=["--memory-request"],
            help="The request for the capacity of the managed instance as an integer number followed by Gi (gigabytes). Example: 4Gi",
        )
        arg_context.argument(
            "storage_class_data",
            options_list=["--storage-class-data", "-d"],
            help="The storage class to be used for data files (.mdf, .ndf). If no value is specified, then no storage "
            "class will be specified, which will result in Kubernetes using the default storage class.",
        )
        arg_context.argument(
            "storage_class_datalogs",
            options_list=["--storage-class-datalogs"],
            help="The storage class to be used for database logs (.ldf). If no value is specified, then no storage "
            "class will be specified, which will result in Kubernetes using the default storage class.",
        )
        arg_context.argument(
            "storage_class_logs",
            options_list=["--storage-class-logs", "-g"],
            help="The storage class to be used for logs (/var/log). If no value is specified, then no storage "
            "class will be specified, which will result in Kubernetes using the default storage class.",
        )
        arg_context.argument(
            "storage_class_backups",
            options_list=["--storage-class-backups"],
            help="The storage class to be used for backups (/var/opt/mssql/backups). If no value is specified, then no storage "
            "class will be specified, which will result in Kubernetes using the default storage class.",
        )
        arg_context.argument(
            "volume_size_data",
            options_list=["--volume-size-data"],
            help="The size of the storage volume to be used for data as a positive number followed by Ki (kilobytes), Mi (megabytes), or Gi (gigabytes).",
        )
        arg_context.argument(
            "volume_size_datalogs",
            options_list=["--volume-size-datalogs"],
            help="The size of the storage volume to be used for data logs as a positive number followed by Ki (kilobytes), Mi (megabytes), or Gi (gigabytes).",
        )
        arg_context.argument(
            "volume_size_logs",
            options_list=["--volume-size-logs"],
            help="The size of the storage volume to be used for logs as a positive number followed by Ki (kilobytes), Mi (megabytes), or Gi (gigabytes).",
        )
        arg_context.argument(
            "volume_size_backups",
            options_list=["--volume-size-backups"],
            help="The size of the storage volume to be used for backups as a positive number followed by Ki (kilobytes), Mi (megabytes), or Gi (gigabytes).",
        )
        arg_context.argument(
            "labels",
            options_list=["--labels"],
            help="Comma-separated list of labels of the SQL managed instance.",
        )
        arg_context.argument(
            "annotations",
            options_list=["--annotations"],
            help="Comma-separated list of annotations of the SQL managed instance.",
        )

        arg_context.argument(
            "service_labels",
            options_list=["--service-labels"],
            help="Comma-separated list of labels to apply to all external services.",
        )

        arg_context.argument(
            "service_annotations",
            options_list=["--service-annotations"],
            help="Comma-separated list of annotations to apply to all external services.",
        )

        arg_context.argument(
            "storage_labels",
            options_list=["--storage-labels"],
            help="Comma-separated list of labels to apply to all PVCs.",
        )

        arg_context.argument(
            "storage_annotations",
            options_list=["--storage-annotations"],
            help="Comma-separated list of annotations to apply to all PVCs.",
        )

        arg_context.argument(
            "noexternal_endpoint",
            options_list=["--no-external-endpoint"],
            action="store_true",
            help="If specified, no external service will be created. Otherwise, an external service will be created "
            "using the same service type as the data controller.",
        )
        arg_context.argument(
            "certificate_public_key_file",
            options_list=["--cert-public-key-file"],
            help="Path to the file containing a PEM formatted certificate public key to be used for SQL Server.",
        )
        arg_context.argument(
            "certificate_private_key_file",
            options_list=["--cert-private-key-file"],
            help="Path to the file containing a PEM formatted certificate private key to be used for SQL Server.",
        )
        arg_context.argument(
            "service_certificate_secret",
            options_list=["--service-cert-secret"],
            help="Name of the Kubernetes secret to generate that hosts or will host SQL service certificate.",
        )
        arg_context.argument(
            "admin_login_secret",
            options_list=["--admin-login-secret"],
            help="Name of the Kubernetes secret to generate that hosts or will host user admin login account credential.",
        )
        arg_context.argument(
            "nowait",
            options_list=["--no-wait"],
            action="store_true",
            help="If given, the command will not wait for the instance to be in a ready state before returning.",
        )
        arg_context.argument(
            "license_type",
            options_list=["--license-type", "-l"],
            help="The license type to apply for this managed instance. {}".format(
                SQLMI_LICENSE_TYPE_ALLOWED_VALUES_MSG_CREATE
            ),
        )
        arg_context.argument(
            "tier",
            options_list=["--tier", "-t"],
            help="The pricing tier for the instance. {}".format(
                SQLMI_TIER_ALLOWED_VALUES_MSG_CREATE
            ),
        )
        arg_context.argument(
            "use_k8s",
            options_list=("--use-k8s"),
            action="store_true",
            help="Create SQL managed instance using local Kubernetes APIs.",
        )
        arg_context.argument(
            "collation",
            options_list=["--collation"],
            help="The SQL Server collation for the instance.",
        )
        arg_context.argument(
            "language",
            options_list=["--language"],
            help="The SQL Server locale to any supported language identifier (LCID) for the instance.",
        )
        arg_context.argument(
            "agent_enabled",
            options_list=["--agent-enabled"],
            help="Enable SQL Server agent for the instance. Default is disabled. Allowed values are 'true' or 'false'.",
        )
        arg_context.argument(
            "trace_flags",
            options_list=["--trace-flags"],
            help="Comma separated list of traceflags. No flags by default.",
        )
        arg_context.argument(
            "time_zone",
            options_list=["--time-zone"],
            help="The SQL Server time zone for the instance.",
        )

    with ArgumentsContext(self, "sql mi-arc edit") as arg_context:
        arg_context.argument(
            "path",
            options_list=["--path"],
            help="The path to the azext_arcdata file for the SQL managed instance json file.",
        )
        arg_context.argument(
            "name",
            options_list=["--name", "-n"],
            help="The name of the SQL managed instance that is being edited. The name under which your "
            "instance is deployed cannot be changed.",
        )
        arg_context.argument(
            "namespace",
            options_list=["--k8s-namespace", "-k"],
            help="Namespace where the SQL managed instance exists. "
            "If no namespace is specified, then the namespace defined "
            "in the kubeconfig will be used.",
        )
        arg_context.argument(
            "dev",
            options_list=["--dev"],
            action="store_true",
            help="If this is specified, then it is considered a dev instance and will not be billed for.",
        )
        arg_context.argument(
            "cores_limit",
            options_list=["--cores-limit", "-c"],
            help="The cores limit of the managed instance as an integer.",
        )
        arg_context.argument(
            "cores_request",
            options_list=["--cores-request"],
            help="The request for cores of the managed instance as an integer.",
        )
        arg_context.argument(
            "memory_limit",
            options_list=["--memory-limit", "-m"],
            help="The limit of the capacity of the managed instance as an integer number followed by Gi (gigabytes). Example: 4Gi",
        )
        arg_context.argument(
            "memory_request",
            options_list=["--memory-request"],
            help="The request for the capacity of the managed instance as an integer number followed by Gi (gigabytes). Example: 4Gi",
        )
        arg_context.argument(
            "nowait",
            options_list=["--no-wait"],
            action="store_true",
            help="If given, the command will not wait for the instance to be in a ready state before returning.",
        )
        arg_context.argument(
            "labels",
            options_list=["--labels"],
            help="Comma-separated list of labels of the SQL managed instance.",
        )
        arg_context.argument(
            "annotations",
            options_list=["--annotations"],
            help="Comma-separated list of annotations of the SQL managed "
            "instance.",
        )
        arg_context.argument(
            "service_labels",
            options_list=["--service-labels"],
            help="Comma-separated list of labels to apply to all external "
            "services.",
        )
        arg_context.argument(
            "service_annotations",
            options_list=["--service-annotations"],
            help="Comma-separated list of annotations to apply to all external "
            "services.",
        )
        arg_context.argument(
            "agent_enabled",
            options_list=["--agent-enabled"],
            help="Enable SQL Server agent for the instance. Default is disabled.",
        )
        arg_context.argument(
            "trace_flags",
            options_list=["--trace-flags"],
            help="Comma separated list of traceflags. No flags by default.",
        )
        arg_context.argument(
            "use_k8s",
            options_list=("--use-k8s"),
            action="store_true",
            help=USE_K8S_TEXT,
        )

    with ArgumentsContext(self, "sql mi-arc delete") as arg_context:
        arg_context.argument(
            "name",
            options_list=["--name", "-n"],
            help="The name of the SQL managed instance to be deleted.",
        )
        arg_context.argument(
            "namespace",
            options_list=["--k8s-namespace", "-k"],
            help="Namespace where the SQL managed instance exists. "
            "If no namespace is specified, then the namespace defined "
            "in the kubeconfig will be used.",
        )
        arg_context.argument(
            "use_k8s",
            options_list=("--use-k8s"),
            action="store_true",
            help=USE_K8S_TEXT,
        )

    with ArgumentsContext(self, "sql mi-arc show") as arg_context:
        arg_context.argument(
            "name",
            options_list=["--name", "-n"],
            help="The name of the SQL managed instance to be shown.",
        )
        arg_context.argument(
            "namespace",
            options_list=["--k8s-namespace", "-k"],
            help="Namespace where the SQL managed instance exists. "
            "If no namespace is specified, then the namespace defined "
            "in the kubeconfig will be used.",
        )
        arg_context.argument(
            "path",
            options_list=["--path", "-p"],
            help="A path where the full specification for the SQL managed instance should be "
            "written. If omitted, the specification will be written to standard output.",
        )
        arg_context.argument(
            "use_k8s",
            options_list=("--use-k8s"),
            action="store_true",
            help=USE_K8S_TEXT,
        )

    with ArgumentsContext(self, "sql mi-arc list") as arg_context:
        arg_context.argument(
            "namespace",
            options_list=["--k8s-namespace", "-k"],
            help="Namespace where the SQL managed instances exist. "
            "If no namespace is specified, then the namespace defined "
            "in the kubeconfig will be used.",
        )
        arg_context.argument(
            "use_k8s",
            options_list=("--use-k8s"),
            action="store_true",
            help=USE_K8S_TEXT,
        )

    with ArgumentsContext(self, "sql mi-arc endpoint list") as arg_context:
        arg_context.argument(
            "name",
            options_list=["--name", "-n"],
            help="The name of the SQL instance to be shown. If omitted, all endpoints for all instances will "
            "be shown.",
        )
        arg_context.argument(
            "namespace",
            options_list=["--k8s-namespace", "-k"],
            help="Namespace where the SQL managed instances exist. "
            "If no namespace is specified, then the namespace defined "
            "in the kubeconfig will be used.",
        )
        arg_context.argument(
            "use_k8s",
            options_list=("--use-k8s"),
            action="store_true",
            help=USE_K8S_TEXT,
        )

    with ArgumentsContext(self, "sql mi-arc config init") as arg_context:
        arg_context.argument(
            "path",
            options_list=["--path", "-p"],
            help="A path where the CRD and specification for the SQL managed instance should be "
            "written.",
        )

    with ArgumentsContext(self, "sql mi-arc config add") as arg_context:
        arg_context.argument(
            "path",
            options_list=("--path", "-p"),
            help="Path to the custom resource specification, i.e. custom/spec.json",
        )

        arg_context.argument(
            "json_values",
            options_list=("--json-values", "-j"),
            help="A key value pair list of json paths to values: key1.subkey1=value1,key2.subkey2=value2. "
            "You may provide inline json values such as: "
            'key=\'{"kind":"cluster","name":"test-cluster"}\' or provide a file path, such as'
            " key=./values.json. The add command does NOT support conditionals.  "
            "If the inline value you are providing is a key "
            'value pair itself with "=" and "," please escape those characters.  '
            'For example, key1="key2\=val2\,key3\=val3". '
            "Please see http://jsonpatch.com/ for "
            "examples of how your path should look.  If you would like to access an array, you must do so "
            "by indicating the index, such as key.0=value",
        )

    with ArgumentsContext(self, "sql mi-arc config replace") as arg_context:
        arg_context.argument(
            "path",
            options_list=("--path", "-p"),
            help="Path to the custom resource specification, i.e. custom/spec.json",
        )

        arg_context.argument(
            "json_values",
            options_list=("--json-values", "-j"),
            help="A key value pair list of json paths to values: key1.subkey1=value1,key2.subkey2=value2. "
            "You may provide inline json values such as: "
            'key=\'{"kind":"cluster","name":"test-cluster"}\' or provide a file path, such as'
            " key=./values.json. The replace command supports conditionals through the jsonpath library.  To use this, "
            "start your path with a $. This will allow you to do a conditional "
            'such as -j $.key1.key2[?(@.key3=="someValue"].key4=value. '
            "If the inline value you are providing is a key "
            'value pair itself with "=" and "," please escape those characters.  '
            'For example, key1="key2\=val2\,key3\=val3". '
            "You may see examples below. "
            "For additional help, please see: https://jsonpath.com/",
        )

    with ArgumentsContext(self, "sql mi-arc config remove") as arg_context:
        arg_context.argument(
            "path",
            options_list=("--path", "-p"),
            help="Path to the custom resource specification, i.e. custom/spec.json",
        )

        arg_context.argument(
            "json_path",
            options_list=("--json-path", "-j"),
            help="A list of json paths based on the jsonpatch library that indicates which values you would like "
            "removed, such as: key1.subkey1,key2.subkey2. The remove command does NOT support conditionals. "
            "Please see http://jsonpatch.com/ for "
            "examples of how your path should look.  If you would like to access an array, you must do so "
            "by indicating the index, such as key.0=value",
        )

    with ArgumentsContext(self, "sql mi-arc config patch") as arg_context:
        arg_context.argument(
            "path",
            options_list=("--path", "-p"),
            help="Path to the custom resource specification, i.e. custom/spec.json",
        )

        arg_context.argument(
            "patch_file",
            options_list=("--patch-file"),
            help="Path to a patch json file that is based off the jsonpatch library: http://jsonpatch.com/. "
            'You must start your patch json file with a key called "patch", whose value is an array '
            "of patch operations you intend to make. "
            "For the path of a patch operation, you may use dot notation, such as key1.key2 for most operations."
            " If you would like to do a replace operation, and you are replacing a value in an array that "
            "requires a conditional, please use the jsonpath notation by beginning your path with a $. "
            'This will allow you to do a conditional such as $.key1.key2[?(@.key3=="someValue"].key4. '
            "Please see the examples below. For additional help with conditionals, "
            "please see: https://jsonpath.com/.",
        )

    with ArgumentsContext(self, "sql mi-arc dag create") as arg_context:
        arg_context.argument(
            "name",
            options_list=["--name", "-n"],
            help="The name of the distributed availability group resource.",
        )
        arg_context.argument(
            "dag_name",
            options_list=["--dag-name"],
            help="The name of the distributed availability group for this SQL managed instance. Both local and remote have to use the same name.",
        )
        arg_context.argument(
            "local_name",
            options_list=["--local-name"],
            help="The name of the local SQL managed instance",
        )
        arg_context.argument(
            "local_primary",
            options_list=["--local-primary"],
            help="True indicates local SQL managed instance is geo primary. False indicates local SQL managed instance is geo secondary",
        )
        arg_context.argument(
            "remote_name",
            options_list=["--remote-name"],
            help="The name of the remote SQL managed instance or remote SQL availability group",
        )
        arg_context.argument(
            "remote_url",
            options_list=["--remote-url"],
            help="The mirroring endpoint URL of the remote SQL managed instance or remote SQL availability group",
        )
        arg_context.argument(
            "remote_cert_file",
            options_list=["--remote-cert-file"],
            help="The filename of mirroring endpoint public certficate for the remote SQL managed instance or remote SQL availability group. Only PEM format is supported",
        )
        arg_context.argument(
            "path",
            options_list=["--path"],
            help="Path to the custom resource specification, i.e. custom/spec.json",
        )
        arg_context.argument(
            "namespace",
            options_list=["--k8s-namespace", "-k"],
            help="Namespace where the SQL managed instance exists. "
            "If no namespace is specified, then the namespace defined "
            "in the kubeconfig will be used.",
        )
        arg_context.argument(
            "use_k8s",
            options_list=("--use-k8s"),
            action="store_true",
            help=USE_K8S_TEXT,
        )

    with ArgumentsContext(self, "sql mi-arc dag delete") as arg_context:
        arg_context.argument(
            "name",
            options_list=["--name"],
            help="The name of the distributed availability group resource.",
        )
        arg_context.argument(
            "namespace",
            options_list=["--k8s-namespace", "-k"],
            help="Namespace where the SQL managed instance exists. "
            "If no namespace is specified, then the namespace defined "
            "in the kubeconfig will be used.",
        )
        arg_context.argument(
            "use_k8s",
            options_list=("--use-k8s"),
            action="store_true",
            help=USE_K8S_TEXT,
        )

    with ArgumentsContext(self, "sql mi-arc dag get") as arg_context:
        arg_context.argument(
            "name",
            options_list=["--name"],
            help="The name of the distributed availability group resource.",
        )
        arg_context.argument(
            "namespace",
            options_list=["--k8s-namespace", "-k"],
            help="Namespace where the SQL managed instance exists. "
            "If no namespace is specified, then the namespace defined "
            "in the kubeconfig will be used.",
        )
        arg_context.argument(
            "use_k8s",
            options_list=("--use-k8s"),
            action="store_true",
            help=USE_K8S_TEXT,
        )

    with ArgumentsContext(self, "sql mi-arc get-mirroring-cert") as arg_context:
        arg_context.argument(
            "name",
            options_list=["--name", "-n"],
            help="The name of the SQL managed instance.",
        )
        arg_context.argument(
            "cert_file",
            options_list=["--cert-file"],
            help="The local filename to store the retrieved certificate in PEM format.",
        )
        arg_context.argument(
            "namespace",
            options_list=["--k8s-namespace", "-k"],
            help="Namespace where the SQL managed instance exists. "
            "If no namespace is specified, then the namespace defined "
            "in the kubeconfig will be used.",
        )
        arg_context.argument(
            "use_k8s",
            options_list=("--use-k8s"),
            action="store_true",
            help=USE_K8S_TEXT,
        )
