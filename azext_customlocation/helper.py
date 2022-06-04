# pylint: disable=line-too-long
# pylint: disable=no-else-return
# pylint: disable=consider-using-in
from knack.util import CLIError
from azure.cli.core.commands.client_factory import get_mgmt_service_client
from azext_customlocation.vendored_sdks.azure.mgmt.extendedlocation import v2021_08_15


# function to Validate that subscription is registered for Custom Locations
def validate_cli_resource_type(cli_ctx, resources):
    resource_client = get_mgmt_service_client(cli_ctx, resources)
    provider = resource_client.providers.get('Microsoft.ExtendedLocation')
    if provider.registration_state != 'Registered':
        raise CLIError('Microsoft.ExtendedLocation provider is not registered.  Run `az provider ' +
                       'register -n Microsoft.ExtendedLocation --wait`.')


def validate_ce_ids(cluster_extension_ids):
    # allow passing in no cluster extensions
    if cluster_extension_ids is None:
        return None
    new_cluster_ex_ids = []
    for ce_id in cluster_extension_ids:
        new_cluster_ex_ids.append(ce_id.strip())
    return new_cluster_ex_ids


def validate_identity_param(assign_identity):
    if assign_identity is None:
        return None

    if (assign_identity == v2021_08_15.models.ResourceIdentityType.system_assigned.value) or (assign_identity == v2021_08_15.models.ResourceIdentityType.none.value):
        identity = v2021_08_15.models.Identity(
            type=assign_identity
        )
        return identity
    else:
        raise CLIError('Invalid input for --assign-identity parameter. Accepted values are : "SystemAssigned" or "None"')
