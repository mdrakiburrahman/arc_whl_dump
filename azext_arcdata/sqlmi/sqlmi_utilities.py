import sys
import re
from azext_arcdata.sqlmi.constants import (
    API_GROUP,
    SQLMI_COMMON_API_KWARGS,
    RESOURCE_KIND_PLURAL,
)
import pydash as _
from azext_arcdata.kubernetes_sdk.models.custom_resource import CustomResource
from azext_arcdata.sqlmi.models.sqlmi_cr_model import SqlmiCustomResource
from azext_arcdata.kubernetes_sdk.client import KubernetesClient
from azext_arcdata.kubernetes_sdk.dc.constants import SQLMI_CRD_NAME


def upgrade_sqlmi_instances(
    namespace,
    name=None,
    field_filter=None,
    label_filter=None,
    desired_version=None,
    dry_run=None,
    force=False,
    use_k8s=None,
):
    KubernetesClient.assert_use_k8s(use_k8s)
    upgrade_instances = resolve_sqlmi_instances(
        namespace, name, field_filter, label_filter
    )

    if name and not upgrade_instances:
        raise ValueError("Instance {} does not exist.".format(name))

    if desired_version is None:
        (datacontroller, dc_config) = KubernetesClient.get_arc_datacontroller(
            namespace, use_k8s
        )
        desired_version = _.get(datacontroller, "spec.docker.imageTag")

    if dry_run:
        sys.stdout.write("****Dry Run****\n")
        sys.stdout.write(
            "{0} instance(s) would be upgraded by this command. \n".format(
                len(upgrade_instances)
            )
        )
        for ss in upgrade_instances:
            # todo: use running version if available post ga+1
            sys.stdout.write(
                "{0} would be upgraded to {1}.\n".format(
                    ss.metadata.name, desired_version
                )
            )
        return upgrade_instances

    # upgrade instances

    patch = {"spec": {"update": {"desiredVersion": desired_version}}}

    for ss in upgrade_instances:
        # todo: use running version if available post ga+1
        sys.stdout.write(
            "Upgrading {0} to {1}.\n".format(ss.metadata.name, desired_version)
        )

    patch_all_namespaced_objects(upgrade_instances, namespace, patch)

    return upgrade_instances


def resolve_sqlmi_instances(
    namespace,
    name=None,
    field_filter=None,
    label_filter=None,
    desired_version=None,
) -> list:

    client = KubernetesClient.resolve_k8s_client().CustomObjectsApi()

    response = client.list_namespaced_custom_object(
        namespace=namespace,
        field_selector=field_filter,
        label_selector=label_filter,
        group=API_GROUP,
        version=KubernetesClient.get_crd_version(SQLMI_CRD_NAME),
        plural=RESOURCE_KIND_PLURAL,
    )

    items = response.get("items")

    instances = _.map_(
        items, lambda cr: CustomResource.decode(SqlmiCustomResource, cr)
    )

    if name is not None:
        instances = _.filter_(
            instances, lambda i: re.match(name, i.metadata.name)
        )

    return instances


def patch_all_namespaced_objects(instances: list, namespace, body):
    for instance in instances:
        KubernetesClient.merge_namespaced_custom_object(
            name=instance.metadata.name,
            namespace=namespace,
            body=body,
            group=API_GROUP,
            version=KubernetesClient.get_crd_version(SQLMI_CRD_NAME),
            plural=RESOURCE_KIND_PLURAL,
        )
