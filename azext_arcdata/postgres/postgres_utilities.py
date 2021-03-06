import sys
import re
from azext_arcdata.postgres.constants import API_GROUP, RESOURCE_KIND, RESOURCE_KIND_PLURAL
import pydash as _
from azext_arcdata.kubernetes_sdk.models.custom_resource import CustomResource
from azext_arcdata.postgres.models.postgres_cr_model import PostgresqlCustomResource
from azext_arcdata.kubernetes_sdk.client import KubernetesClient
from azext_arcdata.kubernetes_sdk.dc.constants import POSTGRES_CRD_NAME


def resolve_postgres_instances(
    namespace,
    name=None,
    field_filter=None,
    label_filter=None,
    desired_version=None
) -> list:
    
    client = KubernetesClient .resolve_k8s_client().CustomObjectsApi()

    response = client.list_namespaced_custom_object(
        namespace=namespace,
        field_selector=field_filter, 
        label_selector=label_filter,
        group=API_GROUP, 
        version=KubernetesClient.get_crd_version(POSTGRES_CRD_NAME), 
        plural=RESOURCE_KIND_PLURAL
    )

    items = response.get("items")

    instances = _.map_(items, lambda cr: CustomResource.decode(PostgresqlCustomResource, cr))
   
    if(name is not None):
        instances = _.filter_(instances, lambda i: re.match(name, i.metadata.name))

    return instances
