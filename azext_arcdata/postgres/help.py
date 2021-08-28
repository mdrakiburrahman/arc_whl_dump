# ------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# -----------------------------------------------------------------------------

from knack.help_files import helps

# ------------------------------------------------------------------------------
# Server Commands
# ------------------------------------------------------------------------------

# pylint: disable=line-too-long
helps[
    "postgres arc-server"
] = """
    type: group
    short-summary: {short}
""".format(
    short="Manage Azure Arc enabled PostgreSQL Hyperscale server groups."
)

helps[
    "postgres arc-server create"
] = """
    type: command
    short-summary: {short}
    long-summary: {long}
    examples:
        - name: {ex1}
          text: >
            az postgres arc-server create -n pg1 --k8s-namespace namespace --use-k8s
        - name: {ex2}
          text: >
            az postgres arc-server create -n pg1 --engine-settings "key1=val1" --k8s-namespace namespace 

            az postgres arc-server create -n pg1 --engine-settings 'key2=val2' --k8s-namespace namespace --use-k8s
        - name: {ex3}
          text: >
            az postgres arc-server create -n pg1 --volume-claim-mounts backup-pvc:backup 
        - name: {ex4}
          text: >
            az postgres arc-server create -n pg1 --memory-limit "coordinator=2Gi,w=1Gi" --workers 1 --k8s-namespace namespace --use-k8s
""".format(
    short="Create an Azure Arc enabled PostgreSQL Hyperscale server group.",
    long="To set the password of the server group, please set the environment variable AZDATA_PASSWORD",
    ex1="Create an Azure Arc enabled PostgreSQL Hyperscale server group.",
    ex2="Create an Azure Arc enabled PostgreSQL Hyperscale server group "
    "with engine settings. Both below examples are valid.",
    ex3="Create a PostgreSQL server group with volume claim mounts.",
    ex4="Create a PostgreSQL server group with specific memory-limit for different node roles.",
)

helps[
    "postgres arc-server edit"
] = """
    type: command
    short-summary: {short}
    examples:
        - name: {ex1}
          text: >
            az postgres arc-server edit --path ./spec.json -n pg1 --k8s-namespace namespace --use-k8s
        - name: {ex2}
          text: >
            az postgres arc-server edit -n pg1 --coordinator-settings 'key2=val2' --k8s-namespace namespace
        - name: {ex3}
          text: >
            az postgres arc-server edit -n pg1 --engine-settings 'key1=val1' --replace-settings --k8s-namespace namespace
""".format(
    short="Edit the configuration of an Azure Arc enabled PostgreSQL Hyperscale server group.",
    ex1="Edit the configuration of an Azure Arc enabled PostgreSQL Hyperscale server group.",
    ex2="Edit an Azure Arc enabled PostgreSQL Hyperscale server group with engine settings for the coordinator node.",
    ex3="Edits an Azure Arc enabled PostgreSQL Hyperscale server group and replaces existing "
    "engine settings with new setting key1=val1.",
)

helps[
    "postgres arc-server delete"
] = """
    type: command
    short-summary: {short}
    examples:
        - name: {ex1}
          text: >
            az postgres arc-server delete -n pg1 --k8s-namespace namespace --use-k8s
""".format(
    short="Delete an Azure Arc enabled PostgreSQL Hyperscale server group.",
    ex1="Delete an Azure Arc enabled PostgreSQL Hyperscale server group.",
)

helps[
    "postgres arc-server show"
] = """
    type: command
    short-summary: {short}
    examples:
        - name: {ex1}
          text: >
            az postgres arc-server show -n pg1 --k8s-namespace namespace --use-k8s
""".format(
    short="Show the details of an Azure Arc enabled PostgreSQL Hyperscale server group.",
    ex1="Show the details of an Azure Arc enabled PostgreSQL Hyperscale server group.",
)

helps[
    "postgres arc-server list"
] = """
    type: command
    short-summary: {short}
    examples:
        - name: {ex1}
          text: >            
            az postgres arc-server list --k8s-namespace namespace --use-k8s
""".format(
    short="List Azure Arc enabled PostgreSQL Hyperscale server groups.",
    ex1="List Azure Arc enabled PostgreSQL Hyperscale server groups.",
)

helps[
    "postgres arc-server endpoint"
] = """
    type: group
    short-summary: {short}
""".format(
    short="Manage Azure Arc enabled PostgreSQL Hyperscale server group endpoints."
)

helps[
    "postgres arc-server endpoint list"
] = """
    type: command
    short-summary: {short}
    examples:
        - name: {ex1}
          text: >
            az postgres arc-server endpoint list --name postgres01 
            --k8s-namespace namespace --use-k8s
""".format(
    short="List Azure Arc enabled PostgreSQL Hyperscale server group endpoints.",
    ex1="List Azure Arc enabled PostgreSQL Hyperscale server group endpoints.",
)

# # pylint: disable=line-too-long
# helps[
#     "postgres arc-server config"
# ] = """
#     type: group
#     short-summary: {short}
# """.format(
#     short="Configuration commands."
# )

# # pylint: disable=line-too-long
# helps[
#     "postgres arc-server config init"
# ] = """
#     type: command
#     short-summary: {short}
#     examples:
#         - name: {ex1}
#           text: >
#             az postgres arc-server config init --path ./template
# """.format(
#     short="Initializes the CRD and specification files for an Azure "
#     "Arc enabled PostgreSQL Hyperscale server group.",
#     ex1="Initializes the CRD and specification files for an Azure "
#     "Arc enabled PostgreSQL Hyperscale server group.",
# )

# # pylint: disable=line-too-long
# helps[
#     "postgres arc-server config add"
# ] = """
#     type: command
#     short-summary: {short}
#     long-summary: {long}
#     examples:
#         - name: {ex1}
#           text: >
#             az postgres arc-server config add --path custom/spec.json
#             --json-values 'spec.storage={val1}'
# """.format(
#     short="Add a value for a json path in a config file.",
#     long="Adds the value at the json path in the config file.  All examples "
#     "below are given in Bash.  If using another command line, please be aware that you may need to escape"
#     "quotations appropriately.  Alternatively, you may use the patch file functionality.",
#     ex1="Ex 1 - Add storage.",
#     val1='{"accessMode":"ReadWriteOnce","className":"managed-premium","size":"10Gi"}',
# )

# # pylint: disable=line-too-long
# helps[
#     "postgres arc-server config remove"
# ] = """
#     type: command
#     short-summary: {short}
#     long-summary: {long}
#     examples:
#         - name: {ex1}
#           text: >
#             az postgres arc-server config remove --path custom/spec.json
#             --json-path '.spec.storage'
# """.format(
#     short="Remove a value for a json path in a config file.",
#     long="Removes the value at the json path in the config file.  All examples "
#     "below are given in Bash.  If using another command line, please be aware that you may need to escape"
#     "quotations appropriately.  Alternatively, you may use the patch file functionality.",
#     ex1="Ex 1 - Remove storage.",
# )

# # pylint: disable=line-too-long
# helps[
#     "postgres arc-server config replace"
# ] = """
#     type: command
#     short-summary: {short}
#     long-summary: {long}
#     examples:
#         - name: {ex1}
#           text: >
#             az postgres arc-server config replace --path custom/spec.json
#             --json-values '$.spec.endpoints[?(@.name=="Controller")].port=30080'
#         - name: {ex2}
#           text: >
#             az postgres arc-server config replace --path custom/spec.json
#             --json-values '{val2}'
# """.format(
#     short="Replace a value for a json path in a config file.",
#     long="Replaces the value at the json path in the config file.  All examples"
#     "below are given in Bash.  If using another command line, please be aware that you may need to escape"
#     "quotations appropriately.  Alternatively, you may use the patch file functionality.",
#     ex1="Ex 1 - Replace the port of a single endpoint.",
#     ex2="Ex 2 - Replace storage.",
#     val2='spec.storage={"accessMode":"ReadWriteOnce","className":"managed-premium","size":"10Gi"}',
# )

# # pylint: disable=line-too-long
# helps[
#     "postgres arc-server config patch"
# ] = """
#     type: command
#     short-summary: {short}
#     long-summary: {long}
#     examples:
#         - name: {ex1}
#           text: >
#             az postgres arc-server config patch --path custom/spec.json --patch ./patch.json

#                 Patch File Example (patch.json):
#                     {patch1}
#         - name: {ex2}
#           text: >
#             az postgres arc-server config patch --path custom/spec.json --patch ./patch.json

#                 Patch File Example (patch.json):
#                     {patch2}
# """.format(
#     short="Patches a config file based on a json patch file.",
#     long="Patches the config file according to the given patch file. "
#     "Please consult http://jsonpatch.com/ for a better understanding of how the paths should be composed. "
#     "The replace operation can use conditionals in its path due to the jsonpath library https://jsonpath.com/. "
#     'All patch json files must start with a key of "patch" that has an array of patches with their '
#     "corresponding op (add, replace, remove), path, and value. "
#     'The "remove" op does not require a value, just a path. '
#     "Please see the examples below.",
#     ex1="Ex 1 - Replace the port of a single endpoint with patch file.",
#     patch1='{"patch":[{"op":"replace","path":"$.spec.endpoints[?(@.name==\'Controller\')].port",'
#     '"value":30080}]}',
#     ex2="Ex 2 - Replace storage with patch file.",
#     patch2='{"patch":[{"op":"replace","path":".spec.storage",'
#     '"value":{"accessMode":"ReadWriteMany","className":"managed-premium","size":"10Gi"}}]}',
# )
