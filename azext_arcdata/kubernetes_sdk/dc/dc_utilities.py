import array
from azext_arcdata.core.constants import DATA_CONTROLLER_PLURAL
from azext_arcdata.kubernetes_sdk.arc_docker_image_service import (
    ArcDataImageService,
)
from azext_arcdata.kubernetes_sdk.client import KubernetesClient
from knack.cli import CLIError

# from azext_arcdata.kubernetes_sdk.dc.client import DataControllerClient
import pydash as _
from colorama import Fore


def resolve_valid_target_version(namespace, target=None, use_k8s=True):
    """
    Validates and returns the valid target version.
    If the target version is passed in, it will be validated for version
    format, and the existance of the version in the registry that is tied to
    the namespace datacontroller.
    If the Target is invalid or does not exist, an exception will be thrown.
    """

    validVersions = ArcDataImageService.get_available_image_versions(
        namespace, use_k8s
    )

    if target is None:
        target = validVersions[0]

    if target is None:
        raise ValueError(
            "Latest image version could not be retrieved from the docker "
            "registry associated with the namespace {0}, please provide a "
            "target version.".format(namespace)
        )

    if ArcDataImageService.validate_image_tag(target) is False:
        raise ValueError("Invalid image version specified {0}".format(target))

    return target


def is_v1(dc):
    """
    Checks is the passed in datacontroller is from the v1 release
    """

    return dc.spec.docker.imageTag.startswith("v1.0")


def upgrade_arc_control_plane(
    client,  #: DataControllerClient,
    namespace,
    target=None,
    dry_run=None,
    use_k8s=True,
):
    KubernetesClient.assert_use_k8s(use_k8s)

    if target is None:
        target = resolve_valid_target_version(
            namespace, target, use_k8s
        )  # validate the target
        #  version before attempting the upgrade
    else:
        if ArcDataImageService.validate_image_tag(target) is False:
            client.stdout(
                "Could not validate version: {0}".format(target),
                color=Fore.YELLOW,
            )

    if dry_run:
        client.stdout("****Dry Run****")
        client.stdout(
            "Arcdata Control Plane would be upgraded to: {0}".format(target)
        )
        return

        # create priviliged service acocunts
    client.create_upgrade_service_account(namespace)

    # create the privileged job which will run the upgrade
    client.create_bootstrapper_privileged_job(namespace, target)

    dc, _ = KubernetesClient.get_arc_datacontroller(namespace, use_k8s)

    if is_v1(dc):
        """
        In upgrades from GA, the data controller replicaset needs to be pre-patched
        to avoid the webhook from rejecting the image tag update. This only needs to be run
        in upgrade from GA. In GA + 1 this logic has been moved into the bootstrapper.
        """
        patch_all_dc_replicaset_images(namespace, target)
        client.await_dc_replicaset_update_completion(namespace, target)

    #  upgrade data_controller_desired_version
    set_data_controller_desired_version(namespace, target, use_k8s)


def patch_all_dc_replicaset_images(namespace, target):
    """
    Temporary method to get us from GA to GA+1, a race condition may cause a
    failure in
    """
    try:
        client = KubernetesClient.resolve_k8s_client().AppsV1Api()

        controller_rs = client.list_namespaced_replica_set(
            namespace=namespace,
            label_selector="app=controller",
        )

        controller_rs = controller_rs.items[0]
        for container in controller_rs.spec.template.spec.containers:
            (
                registry,
                repository,
                image_name,
                image_tag,
            ) = ArcDataImageService.parse_image_uri(container.image)
            container.image = ArcDataImageService.format_image_uri(
                registry, repository, image_name, target
            )

        client.patch_namespaced_replica_set(
            name=controller_rs.metadata.name,
            namespace=namespace,
            body=controller_rs,
        )

        restart_owned_pods(
            namespace=namespace,
            replicaset_name=controller_rs.metadata.name,
            use_k8s=True,
        )

    except Exception as e:
        raise CLIError(e)


def get_bootstrapper_deployment(namespace: str, use_k8s: bool = True):
    """
    Return the bootstrapper custom resource for the given namespace.
    """
    KubernetesClient.assert_use_k8s(use_k8s)

    try:
        client = KubernetesClient.resolve_k8s_client().AppsV1Api()

        response = client.list_namespaced_deployment(
            namespace=namespace,
            label_selector="app=bootstrapper",
        )

        return response.items[0]

    except Exception as e:
        raise CLIError(e)


def restart_owned_pods(namespace: str, replicaset_name: str, use_k8s=True):
    KubernetesClient.assert_use_k8s(use_k8s)

    owned_pods = select_owned_pods(namespace, replicaset_name)

    client = KubernetesClient.resolve_k8s_client().CoreV1Api()

    for pod in owned_pods:
        client.delete_namespaced_pod(pod.metadata.name, namespace)


def set_data_controller_desired_version(
    namespace: str, desired_version: str, use_k8s=True
):
    dc, config = KubernetesClient.get_arc_datacontroller(namespace, use_k8s)

    desiredVersionPatch = {"spec": {"docker": {"imageTag": desired_version}}}

    KubernetesClient.merge_namespaced_custom_object(
        desiredVersionPatch,
        plural=DATA_CONTROLLER_PLURAL,
        name=dc.metadata.name,
        namespace=namespace,
        group=dc.group,
        version=dc.version,
    )
    dc, config = KubernetesClient.get_arc_datacontroller(namespace, use_k8s)
    return dc


def select_owned_pods(namespace: str, owned_by: str) -> array.array:
    """
    returns a list of pods which are owned by the owned_by name using the
    metadata.ownerReference.name property
    """
    client = KubernetesClient.resolve_k8s_client().CoreV1Api()
    pods = client.list_namespaced_pod(namespace).items
    return filter_owned_pods(pods, owned_by)


def filter_owned_pods(pods: array.array, owned_by: str):
    owned_pods = _.filter_(
        pods,
        lambda p: _.some(
            _.get(p, "metadata.owner_references") or [],
            lambda o: o.name == owned_by,
        ),
    )
    return owned_pods
