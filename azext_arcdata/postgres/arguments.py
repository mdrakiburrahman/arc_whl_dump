# ------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# -----------------------------------------------------------------------------

from azext_arcdata.core.constants import USE_K8S_TEXT


def load_arguments(self, _):
    from knack.arguments import ArgumentsContext

    # ------------------------------------------------------------------------------
    # Server Commands
    # ------------------------------------------------------------------------------

    with ArgumentsContext(self, "postgres arc-server create") as arg_context:
        arg_context.argument(
            "path",
            options_list=["--path"],
            help="The path to the source json file for the Azure Arc enabled PostgreSQL Hyperscale"
            " server group. This is optional.",
        )
        arg_context.argument(
            "name",
            options_list=["--name", "-n"],
            help="Name of the Azure Arc enabled PostgreSQL Hyperscale server group.",
        )
        arg_context.argument(
            "namespace",
            options_list=["--k8s-namespace", "-k"],
            help="The Kubernetes namespace where the Azure Arc enabled PostgreSQL Hyperscale server group is deployed. "
            "If no namespace is specified, then the namespace defined in the kubeconfig will be used.",
        )
        arg_context.argument(
            "replicas",
            options_list=["--replicas", "-r"],
            help="The number of replicas to be deployed for high availability purpose with default of '1'.",
        )
        arg_context.argument(
            "cores_limit",
            options_list=["--cores-limit"],
            help="The maximum number of CPU cores for Azure Arc enabled PostgreSQL Hyperscale server group"
            " that can be used per node. Fractional cores are supported."
            ' Optionally a comma-separated list of roles with values can be specified in format <role>=<value>. Valid roles are: "coordinator" or "c", "worker" or "w".'
            " If no roles are specified, settings will apply to all nodes of the PostgreSQL Hyperscale server group.",
        )
        arg_context.argument(
            "cores_request",
            options_list=["--cores-request"],
            help="The minimum number of CPU cores that must be available per node to schedule the service. "
            "Fractional cores are supported."
            ' Optionally a comma-separated list of roles with values can be specified in format <role>=<value>. Valid roles are: "coordinator" or "c", "worker" or "w".'
            " If no roles are specified, settings will apply to all nodes of the PostgreSQL Hyperscale server group.",
        )
        arg_context.argument(
            "memory_limit",
            options_list=["--memory-limit"],
            help="The memory limit of the Azure Arc enabled PostgreSQL Hyperscale server group as a number"
            " followed by Ki (kilobytes), Mi (megabytes), or Gi (gigabytes)."
            ' Optionally a comma-separated list of roles with values can be specified in format <role>=<value>. Valid roles are: "coordinator" or "c", "worker" or "w".'
            " If no roles are specified, settings will apply to all nodes of the PostgreSQL Hyperscale server group.",
        )
        arg_context.argument(
            "memory_request",
            options_list=["--memory-request"],
            help="The memory request of the Azure Arc enabled PostgreSQL Hyperscale server group as a"
            " number followed by Ki (kilobytes), Mi (megabytes), or Gi (gigabytes)."
            ' Optionally a comma-separated list of roles with values can be specified in format <role>=<value>. Valid roles are: "coordinator" or "c", "worker" or "w".'
            " If no roles are specified, settings will apply to all nodes of the PostgreSQL Hyperscale server group.",
        )
        arg_context.argument(
            "storage_class_data",
            options_list=["--storage-class-data"],
            help="The storage class to be used for data persistent volumes.",
        )
        arg_context.argument(
            "storage_class_logs",
            options_list=["--storage-class-logs"],
            help="The storage class to be used for logs persistent volumes.",
        )
        arg_context.argument(
            "storage_class_backups",
            options_list=["--storage-class-backups"],
            help="The storage class to be used for backup persistent volumes.",
        )
        arg_context.argument(
            "volume_claim_mounts",
            options_list=["--volume-claim-mounts"],
            help="A comma-separated list of volume claim mounts. A volume claim mount is a pair of an existing persistent volume claim "
            "(in the same namespace) and volume type (and optional metadata depending on the volume type) separated by colon."
            "The persistent volume will be mounted in each pod for the PostgreSQL server group. "
            "The mount path may depend on the volume type.",
        )
        arg_context.argument(
            "volume_size_data",
            options_list=["--volume-size-data"],
            help="The size of the storage volume to be used for data as a positive number followed by Ki (kilobytes), Mi (megabytes), or Gi (gigabytes).",
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
            "workers",
            options_list=["--workers", "-w"],
            help="The number of worker nodes to provision in a server group. "
            "In Preview, reducing the number of worker nodes is not supported. Refer to documentation for additional details.",
        )
        arg_context.argument(
            "extensions",
            options_list=("--extensions"),
            help="A comma-separated list of the Postgres extensions that should be loaded on startup. Please refer to the postgres documentation for supported values.",
        )
        arg_context.argument(
            "engine_version",
            type=int,
            options_list=["--engine-version"],
            help="Must be 11 or 12. The default value is 12.",
        )
        arg_context.argument(
            "engine_settings",
            options_list=["--engine-settings"],
            help="A comma separated list of Postgres engine settings in the format 'key1=val1, key2=val2'.",
        )
        arg_context.argument(
            "no_external_endpoint",
            options_list=["--no-external-endpoint"],
            action="store_true",
            help="If specified, no external service will be created. Otherwise, an external service will be created "
            "using the same service type as the data controller.",
        )
        arg_context.argument(
            "use_k8s",
            options_list=("--use-k8s"),
            action="store_true",
            help=USE_K8S_TEXT,
        )

        # arg_context.argument(
        #     'dev',
        #     options_list=['--dev'],
        #     action='store_true',
        #     help='If this is specified, then it is considered a dev instance and will not be billed for.')
        # )
        arg_context.argument("port", options_list=["--port"], help="Optional.")

        arg_context.argument(
            "coordinator_engine_settings",
            options_list=["--coordinator-settings"],
            help="A comma separated list of Postgres engine settings in the format 'key1=val1, key2=val2' to be applied to 'coordinator' node role."
            " When node role specific settings are specified, default settings will be ignored and overridden with the settings provided here.",
        )
        arg_context.argument(
            "worker_engine_settings",
            options_list=["--worker-settings"],
            help="A comma separated list of Postgres engine settings in the format 'key1=val1, key2=val2' to be applied to 'worker' node role."
            " When node role specific settings are specified, default settings will be ignored and overridden with the settings provided here.",
        )
        arg_context.argument(
            "nowait",
            options_list=["--no-wait"],
            action="store_true",
            help="If given, the command will not wait for the instance to be in a ready state before returning.",
        )

    with ArgumentsContext(self, "postgres arc-server edit") as arg_context:
        arg_context.argument(
            "path",
            options_list=["--path"],
            help="The path to the source json file for the Azure Arc enabled PostgreSQL Hyperscale server group. This is optional.",
        )
        arg_context.argument(
            "name",
            options_list=["--name", "-n"],
            help="Name of the Azure Arc enabled PostgreSQL Hyperscale server group that is being edited. The name under which your instance "
            "is deployed cannot be changed.",
        )
        arg_context.argument(
            "namespace",
            options_list=["--k8s-namespace", "-k"],
            help="The Kubernetes namespace where the Azure Arc enabled PostgreSQL Hyperscale server group is deployed. "
            "If no namespace is specified, then the namespace defined in the kubeconfig will be used.",
        )
        arg_context.argument(
            "replicas",
            options_list=["--replicas", "-r"],
            help="The number of replicas to be deployed for high availability purpose with default of '1'.",
        )
        arg_context.argument(
            "cores_limit",
            options_list=["--cores-limit"],
            help="The maximum number of CPU cores for Azure Arc enabled PostgreSQL Hyperscale server group that can be used per node,"
            " fractional cores are supported. To remove the cores_limit, specify its value as empty string."
            ' Optionally a comma-separated list of roles with values can be specified in format <role>=<value>. Valid roles are: "coordinator" or "c", "worker" or "w".'
            " If no roles are specified, settings will apply to all nodes of the PostgreSQL Hyperscale server group.",
        )
        arg_context.argument(
            "cores_request",
            options_list=["--cores-request"],
            help="The minimum number of CPU cores that must be available per node to schedule the service, fractional cores"
            " are supported. To remove the cores_request, specify its value as empty string."
            ' Optionally a comma-separated list of roles with values can be specified in format <role>=<value>. Valid roles are: "coordinator" or "c", "worker" or "w".'
            " If no roles are specified, settings will apply to all nodes of the PostgreSQL Hyperscale server group.",
        )
        arg_context.argument(
            "memory_limit",
            options_list=["--memory-limit"],
            help="The memory limit for Azure Arc enabled PostgreSQL Hyperscale server group as a number followed"
            " by Ki (kilobytes), Mi (megabytes), or Gi (gigabytes). To remove the memory_limit, specify its value as empty string."
            ' Optionally a comma-separated list of roles with values can be specified in format <role>=<value>. Valid roles are: "coordinator" or "c", "worker" or "w".'
            " If no roles are specified, settings will apply to all nodes of the PostgreSQL Hyperscale server group.",
        )
        arg_context.argument(
            "memory_request",
            options_list=["--memory-request"],
            help="The memory request for Azure Arc enabled PostgreSQL Hyperscale server group as a number followed by"
            " Ki (kilobytes), Mi (megabytes), or Gi (gigabytes). To remove the memory_request, specify its value as empty string."
            ' Optionally a comma-separated list of roles with values can be specified in format <role>=<value>. Valid roles are: "coordinator" or "c", "worker" or "w".'
            " If no roles are specified, settings will apply to all nodes of the PostgreSQL Hyperscale server group.",
        )
        arg_context.argument(
            "workers",
            options_list=["--workers", "-w"],
            help="The number of worker nodes to provision in a server group."
            " In Preview, reducing the number of worker nodes is not supported. Refer to documentation for additional details.",
        )
        arg_context.argument(
            "extensions",
            options_list=["--extensions"],
            help="A comma-separated list of the Postgres extensions that should be loaded on startup. Please refer to the postgres documentation for supported values.",
        )
        # arg_context.argument(
        #     'dev',
        #     options_list=['--dev'],
        #     action='store_true',
        #     help='If this is specified, then it is considered a dev instance and will not be billed for.')
        # )
        arg_context.argument("port", options_list=["--port"], help="Optional.")
        arg_context.argument(
            "admin_password",
            options_list=["--admin-password"],
            action="store_true",
            help="If given, the Azure Arc enabled PostgreSQL Hyperscale server group's admin password will be set to the value of the "
            "AZDATA_PASSWORD environment variable if present and a prompted value otherwise.",
        )
        arg_context.argument(
            "nowait",
            options_list=["--no-wait"],
            action="store_true",
            help="If given, the command will not wait for the instance to be in a ready state before returning.",
        )
        arg_context.argument(
            "engine_settings",
            options_list=["--engine-settings"],
            help="A comma separated list of Postgres engine settings in the format 'key1=val1, key2=val2'. The provided settings will be merged with the existing settings."
            " To remove a setting, provide an empty value like 'removedKey='."
            " If you change an engine setting that requires a restart, the service will be restarted to apply the settings immediately.",
        )
        arg_context.argument(
            "replace_engine_settings",
            options_list=["--replace-settings"],
            action="store_true",
            help="When specified with --engine-settings, will replace all existing custom engine settings with new set of settings and values.",
        )
        arg_context.argument(
            "coordinator_engine_settings",
            options_list=["--coordinator-settings"],
            help="A comma separated list of Postgres engine settings in the format 'key1=val1, key2=val2' to be applied to 'coordinator' node role."
            " When node role specific settings are specified, default settings will be ignored and overridden with the settings provided here.",
        )
        arg_context.argument(
            "worker_engine_settings",
            options_list=["--worker-settings"],
            help="A comma separated list of Postgres engine settings in the format 'key1=val1, key2=val2' to be applied to 'worker' node role."
            " When node role specific settings are specified, default settings will be ignored and overridden with the settings provided here.",
        )
        arg_context.argument(
            "use_k8s",
            options_list=["--use-k8s"],
            action="store_true",
            help=USE_K8S_TEXT,
        )

    with ArgumentsContext(self, "postgres arc-server delete") as arg_context:
        arg_context.argument(
            "name",
            options_list=["--name", "-n"],
            help="Name of the Azure Arc enabled PostgreSQL Hyperscale server group.",
        )
        arg_context.argument(
            "namespace",
            options_list=["--k8s-namespace", "-k"],
            help="The Kubernetes namespace where the Azure Arc enabled PostgreSQL Hyperscale server group is deployed. "
            "If no namespace is specified, then the namespace defined in the kubeconfig will be used.",
        )
        arg_context.argument(
            "force",
            options_list=["--force", "-f"],
            action="store_true",
            help="Force delete the Azure Arc enabled PostgreSQL Hyperscale server group without confirmation.",
        )
        arg_context.argument(
            "use_k8s",
            options_list=["--use-k8s"],
            action="store_true",
            help=USE_K8S_TEXT,
        )

    with ArgumentsContext(self, "postgres arc-server show") as arg_context:
        arg_context.argument(
            "name",
            options_list=["--name", "-n"],
            help="Name of the Azure Arc enabled PostgreSQL Hyperscale server group.",
        )
        arg_context.argument(
            "namespace",
            options_list=["--k8s-namespace", "-k"],
            help="The Kubernetes namespace where the Azure Arc enabled PostgreSQL Hyperscale server group is deployed. "
            "If no namespace is specified, then the namespace defined in the kubeconfig will be used.",
        )
        arg_context.argument(
            "path",
            options_list=["--path"],
            help="A path where the full specification for the Azure Arc enabled PostgreSQL Hyperscale server group should be "
            "written. If omitted, the specification will be written to standard output.",
        )
        arg_context.argument(
            "use_k8s",
            options_list=["--use-k8s"],
            action="store_true",
            help=USE_K8S_TEXT,
        )

    with ArgumentsContext(self, "postgres arc-server list") as arg_context:
        arg_context.argument(
            "namespace",
            options_list=["--k8s-namespace", "-k"],
            help="The Kubernetes namespace where the Azure Arc enabled PostgreSQL Hyperscale server groups are deployed. "
            "If no namespace is specified, then the namespace defined in the kubeconfig will be used.",
        )
        arg_context.argument(
            "use_k8s",
            options_list=["--use-k8s"],
            action="store_true",
            help=USE_K8S_TEXT,
        )

    with ArgumentsContext(
        self, "postgres arc-server endpoint list"
    ) as arg_context:
        arg_context.argument(
            "name",
            options_list=["--name", "-n"],
            help="Name of the Azure Arc enabled PostgreSQL Hyperscale server group.",
        )
        arg_context.argument(
            "namespace",
            options_list=["--k8s-namespace", "-k"],
            help="The Kubernetes namespace where the Azure Arc enabled PostgreSQL Hyperscale server group is deployed. "
            "If no namespace is specified, then the namespace defined in the kubeconfig will be used.",
        )
        arg_context.argument(
            "use_k8s",
            options_list=["--use-k8s"],
            action="store_true",
            help=USE_K8S_TEXT,
        )

    with ArgumentsContext(
        self, "postgres arc-server config init"
    ) as arg_context:
        arg_context.argument(
            "path",
            options_list=["--path"],
            help="A path where the CRD and specification for the Azure Arc enabled PostgreSQL Hyperscale server group should be "
            "written.",
        )

    with ArgumentsContext(
        self, "postgres arc-server config add"
    ) as arg_context:
        arg_context.argument(
            "path",
            options_list=["--path"],
            help="Path to the custom resource specification, i.e. custom/spec.json",
        )

        arg_context.argument(
            "json_values",
            options_list=["--json-values", "-j"],
            help="A key value pair list of json paths to values: key1.subkey1=value1,key2.subkey2=value2. "
            "You may provide inline json values such as: "
            'key=\'{"kind":"cluster","name":"test-cluster"}\' or provide a file path, such as'
            " key=./values.json. Add does NOT support conditionals.  "
            "If the inline value you are providing is a key "
            'value pair itself with "=" and "," please escape those characters.  '
            'For example, key1="key2\=val2\,key3\=val3". '
            "Please see http://jsonpatch.com/ for "
            "examples of how your path should look.  If you would like to access an array, you must do so "
            "by indicating the index, such as key.0=value",
        )

    with ArgumentsContext(
        self, "postgres arc-server config replace"
    ) as arg_context:
        arg_context.argument(
            "path",
            options_list=["--path"],
            help="Path to the custom resource specification, i.e. custom/spec.json",
        )

        arg_context.argument(
            "json_values",
            options_list=["--json-values", "-j"],
            help="A key value pair list of json paths to values: key1.subkey1=value1,key2.subkey2=value2. "
            "You may provide inline json values such as: "
            'key=\'{"kind":"cluster","name":"test-cluster"}\' or provide a file path, such as'
            " key=./values.json. Replace supports conditionals through the jsonpath library.  To use this, "
            "start your path with a $. This will allow you to do a conditional "
            'such as -j $.key1.key2[?(@.key3=="someValue"].key4=value. '
            "If the inline value you are providing is a key "
            'value pair itself with "=" and "," please escape those characters.  '
            'For example, key1="key2\=val2\,key3\=val3". '
            "You may see examples below. "
            "For additional help, please see: https://jsonpath.com/",
        )

    with ArgumentsContext(
        self, "postgres arc-server config remove"
    ) as arg_context:
        arg_context.argument(
            "path",
            options_list=["--path"],
            help="Path to the custom resource specification, i.e. custom/spec.json",
        )

        arg_context.argument(
            "json_path",
            options_list=["--json-path", "-j"],
            help="A list of json paths based on the jsonpatch library that indicates which values you would like "
            "removed, such as: key1.subkey1,key2.subkey2. Remove does NOT support conditionals. "
            "Please see http://jsonpatch.com/ for "
            "examples of how your path should look.  If you would like to access an array, you must do so "
            "by indicating the index, such as key.0=value",
        )

    with ArgumentsContext(
        self, "postgres arc-server config patch"
    ) as arg_context:
        arg_context.argument(
            "path",
            options_list=["--path"],
            help="Path to the custom resource specification, i.e. custom/spec.json",
        )

        arg_context.argument(
            "patch_file",
            options_list=["--patch-file"],
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
