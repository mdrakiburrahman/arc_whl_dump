# ------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# ------------------------------------------------------------------------------

from azext_arcdata.kubernetes_sdk.models import (
    CustomResource,
    SerializationUtils,
    StorageSpec,
    KubeQuantity,
    VolumeClaim,
)

from azext_arcdata.core.constants import DNS_NAME_REQUIREMENTS
from azext_arcdata.core.util import name_meets_dns_requirements
from azext_arcdata.core.labels import parse_labels
from azext_arcdata.sqlmi.settings import parse_traceflags, add_to_settings
from azext_arcdata.core.class_utils import (
    enforcetype,
    validator,
    validatedclass,
)

from azext_arcdata.sqlmi.util import (
    validate_sqlmi_license_type,
    validate_sqlmi_tier,
)

from azext_arcdata.sqlmi.constants import (
    SQLMI_LICENSE_TYPE_ALLOWED_VALUES_MSG,
    SQLMI_MIN_MEMORY_SIZE,
    SQLMI_MIN_CORES_SIZE,
    SQLMI_TIER_ALLOWED_VALUES_MSG,
    SQLMI_AGENT_ENABLED,
    SQLMI_COLLATION,
    SQLMI_LANGUAGE_LCID,
    SQLMI_TRACEFLAGS,
    SQLMI_SETTINGS,
    SQLMI_TIMEZONE,
)

from typing import Union, TYPE_CHECKING

# KubernetesClient is only needed for typehints, but causes a circular import.
# This is the python provided workaround
if TYPE_CHECKING:
    from azext_arcdata.kubernetes_sdk.client import KubernetesClient

TYPE_ERROR = "Type '{}' is incompatible with property '{}'"


@validatedclass
class SqlmiCustomResource(CustomResource):
    """
    Internal Sqlmi Custom Resource object to be used for deployments.
    """

    def __init__(
        self,
        spec: "SqlmiCustomResource.Spec" = None,
        metadata: "SlqlmiCustomResource.Metadata" = None,
        *args,
        **kwargs
    ):
        """
        Initializes a CR object with the given json.
        """
        super().__init__(*args, **kwargs)
        self.spec = spec if spec else self.Spec()
        self.metadata = metadata if metadata else self.Metadata()

    class Spec(CustomResource.Spec):
        """
        @override CustomResource.spec
        """

        def __init__(
            self,
            replicas: int = 1,
            serviceType: str = None,
            license_type: str = None,
            tier: str = None,
            *args,
            **kwargs
        ):
            super().__init__(*args, **kwargs)
            self.replicas = replicas
            self.serviceType = serviceType
            self.scheduling = self.Scheduling()
            self.security = self.Security()
            self.tier = tier
            self.license_type = license_type
            self.settings = {}

        @property
        def replicas(self) -> int:
            """
            Default to 1, if replica number > 1, it is a HA deployment
            """
            return self._replicas

        @property
        def tier(self) -> str:
            """
            The tier. Default to None.
            """
            return self._tier

        @property
        def license_type(self) -> str:
            """
            The license type.
            """
            return self._license_type

        @replicas.setter
        def replicas(self, r: int):
            self._replicas = r

        @tier.setter
        def tier(self, t: str):
            self._tier = t

        @license_type.setter
        def license_type(self, l: str):
            self._license_type = l

        @property
        def settings(self):
            return self._settings

        @settings.setter
        def settings(self, s: any):
            self._settings = s

        class Security(SerializationUtils):
            """
            SqlmiCustomResource.Spec.Security
            """

            def __init__(
                self,
                adminLoginSecret: str = None,
                serviceCertificateSecret: str = None,
            ):
                self.adminLoginSecret = (
                    adminLoginSecret if adminLoginSecret else str()
                )
                self.serviceCertificateSecret = (
                    serviceCertificateSecret
                    if serviceCertificateSecret
                    else str()
                )

            @property
            def adminLoginSecret(self) -> str:
                return self._adminLoginSecret

            @adminLoginSecret.setter
            @enforcetype(str)
            def adminLoginSecret(self, s):
                self._adminLoginSecret = s

            @property
            def serviceCertificateSecret(self) -> str:
                return self._serviceCertificateSecret

            @serviceCertificateSecret.setter
            @enforcetype(str)
            def serviceCertificateSecret(self, s):
                self._serviceCertificateSecret = s

            def _hydrate(self, d: dict):
                if "adminLoginSecret" in d:
                    self.adminLoginSecret = d["adminLoginSecret"]
                if "serviceCertificateSecret" in d:
                    self.serviceCertificateSecret = d[
                        "serviceCertificateSecret"
                    ]

            def _to_dict(self):
                return {
                    "adminLoginSecret": self.adminLoginSecret,
                    "serviceCertificateSecret": self.serviceCertificateSecret,
                }

        @property
        def security(self) -> Security:
            return self._security

        @security.setter
        def security(self, s: Security):
            self._security = s

        class Storage(CustomResource.Spec.Storage):
            """
            @override CustomResource.spec.storage
            """

            def __init__(self, datalogs: StorageSpec = None, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.datalogs = datalogs if datalogs else StorageSpec()

            @property
            def datalogs(self) -> StorageSpec:
                return self._datalogs

            @datalogs.setter
            @enforcetype(StorageSpec)
            def datalogs(self, s):
                self._datalogs = s

            def _hydrate(self, d: dict):
                """
                @override
                """
                super()._hydrate(d)
                if "datalogs" in d:
                    self.datalogs._hydrate(d["datalogs"])

            def _to_dict(self):
                """
                @override
                """
                base = super()._to_dict()
                base["datalogs"] = self.datalogs._to_dict()
                return base

        class Scheduling(SerializationUtils):
            """
            CustomResource.spec.scheduling
            """

            def __init__(self):
                # If you add a nested class, please create a property and
                # initialize it here
                #
                self.default = self.Default()

            class Default(SerializationUtils):
                """
                CustomResource.spec.scheduling.default
                """

                def __init__(self):
                    self.resources = self.Resources()

                class Resources:
                    """
                    CustomResource.spec.scheduling.default.resources
                    """

                    def __init__(self):
                        self.requests = self.Requests()
                        self.limits = self.Limits()

                    class Requests(SerializationUtils):
                        """
                        CustomResource.spec.scheduling.default.resources
                        .requests
                        """

                        @property
                        def memory(self) -> KubeQuantity:
                            return self._memory

                        @memory.setter
                        def memory(self, m: Union[str, KubeQuantity]):
                            if type(m) is str and m == "":
                                self._memory = None
                                return

                            val = KubeQuantity(m)
                            if val < SQLMI_MIN_MEMORY_SIZE:
                                raise ValueError(
                                    "Sqlmi memory request must be at least '{"
                                    "}'".format(SQLMI_MIN_MEMORY_SIZE.quantity)
                                )
                            self._memory = KubeQuantity(m)

                        @property
                        def cpu(self) -> KubeQuantity:
                            return self._cpu

                        @cpu.setter
                        def cpu(self, c: Union[str, KubeQuantity]):
                            if type(c) is str and c == "":
                                self._cpu = None
                                return

                            val = KubeQuantity(c)
                            if val < SQLMI_MIN_CORES_SIZE:
                                raise ValueError(
                                    "Sqlmi cpu request must be at least '{"
                                    "}'".format(SQLMI_MIN_CORES_SIZE.quantity)
                                )
                            self._cpu = val

                        def _to_dict(self):
                            """
                            @override
                            """
                            mem = getattr(self, "memory", None)
                            cores = getattr(self, "cpu", None)
                            return {
                                "memory": mem.quantity
                                if mem is not None
                                else mem,
                                "cpu": cores.quantity
                                if cores is not None
                                else cores,
                            }

                        def _hydrate(self, d: dict):
                            if "memory" in d:
                                self.memory = d["memory"]

                            if "cpu" in d:
                                self.cpu = d["cpu"]

                    @property
                    def requests(self) -> Requests:
                        return self._requests

                    @requests.setter
                    def requests(self, r: Requests):
                        self._requests = r

                    class Limits(SerializationUtils):
                        """
                        CustomResource.spec.scheduling.default.resources.limits
                        """

                        @property
                        def memory(self) -> KubeQuantity:
                            return self._memory

                        @memory.setter
                        def memory(self, m: Union[str, KubeQuantity]):
                            if type(m) is str and m == "":
                                self._memory = None
                                return

                            val = KubeQuantity(m)
                            if val < SQLMI_MIN_MEMORY_SIZE:
                                raise ValueError(
                                    "Sqlmi memory limit must be at least '{"
                                    "}'".format(SQLMI_MIN_MEMORY_SIZE.quantity)
                                )
                            self._memory = val

                        @property
                        def cpu(self) -> KubeQuantity:
                            return self._cpu

                        @cpu.setter
                        def cpu(self, c: Union[str, KubeQuantity]):
                            if type(c) is str and c == "":
                                self._cpu = None
                                return

                            val = KubeQuantity(c)
                            if val < SQLMI_MIN_CORES_SIZE:
                                raise ValueError(
                                    "Sqlmi cpu limit must be at least '{"
                                    "}'".format(SQLMI_MIN_CORES_SIZE.quantity)
                                )
                            self._cpu = val

                        def _to_dict(self):
                            """
                            @override
                            """
                            mem = getattr(self, "memory", None)
                            cores = getattr(self, "cpu", None)
                            return {
                                "memory": mem.quantity
                                if mem is not None
                                else mem,
                                "cpu": cores.quantity
                                if cores is not None
                                else cores,
                            }

                        def _hydrate(self, d: dict):
                            """
                            @override
                            """
                            if "memory" in d:
                                self.memory = d["memory"]

                            if "cpu" in d:
                                self.cpu = d["cpu"]

                    @property
                    def limits(self) -> Limits:
                        return self._limits

                    @limits.setter
                    def limits(self, r: Limits):
                        self._limits = r

                    def _to_dict(self):
                        return {
                            "limits": self.limits._to_dict(),
                            "requests": self.requests._to_dict(),
                        }

                    def _hydrate(self, d: dict):
                        if "limits" in d:
                            self.limits._hydrate(d["limits"])
                        if "requests" in d:
                            self.requests._hydrate(d["requests"])

                @property
                def resources(self) -> Resources:
                    return self._resources

                @resources.setter
                def resources(self, r: Resources):
                    self._resources = r

                def _to_dict(self) -> dict:
                    return {"resources": self.resources._to_dict()}

                def _hydrate(self, d: dict):
                    if "resources" in d:
                        self.resources._hydrate(d["resources"])

            @property
            def default(self) -> Default:
                return self._default

            @default.setter
            def default(self, d: Default):
                self._default = d

            def _to_dict(self) -> dict:
                return {"default": self.default._to_dict()}

            def _hydrate(self, d: dict):
                if "default" in d:
                    self.default._hydrate(d["default"])

        @property
        def scheduling(self) -> Scheduling:
            return self._scheduling

        @scheduling.setter
        def scheduling(self, s: Scheduling):
            self._scheduling = s

        def _hydrate(self, d: dict):
            super()._hydrate(d)
            if "replicas" in d:
                self.replicas = d["replicas"]
            if "serviceType" in d:
                self.serviceType = d["serviceType"]
            if "security" in d:
                self.security._hydrate(d["security"])
            if "scheduling" in d:
                self.scheduling._hydrate(d["scheduling"])
            if "tier" in d:
                self.tier = d["tier"]
            if "licenseType" in d:
                self.license_type = d["licenseType"]
            if "settings" in d:
                self.settings = d["settings"]

        def _to_dict(self):
            base = super()._to_dict()
            base["replicas"] = self.replicas
            base["serviceType"] = getattr(self, "serviceType", None)
            base["security"] = self.security._to_dict()
            base["scheduling"] = self.scheduling._to_dict()
            base["tier"] = self.tier
            base["licenseType"] = self.license_type
            base["settings"] = getattr(self, "settings", None)
            return base

    class Metadata(CustomResource.Metadata):
        """
        @override CustomResource.metadata
        """

        arc_sql_name_max_length = 13

        def __init__(self, name: str = None, *args, **kwargs):
            super().__init__(*args, **kwargs)

        @CustomResource.Metadata.name.setter
        def name(self, n: str):
            """
            @override CustomResource.metadata.name.setter
            """
            if not n:
                raise ValueError("SQL MI name cannot be empty")

            if len(n) > self.arc_sql_name_max_length:
                raise ValueError(
                    "SQL MI name '{}' exceeds {} character length limit".format(
                        n, self.arc_sql_name_max_length
                    )
                )

            if not name_meets_dns_requirements(n):
                raise ValueError(
                    "SQL MI name '{}' does not follow DNS requirements: {"
                    "}".format(n, DNS_NAME_REQUIREMENTS)
                )

            self._name = n

        def _hydrate(self, d: dict):
            super()._hydrate(d)

        def _to_dict(self):
            return super()._to_dict()

    class Status(CustomResource.Status):
        """
        @override CustomResource.Status
        """

        def __init__(self):
            super().__init__()

        @property
        def readyReplicas(self) -> int:
            """
            If this resource is a ReplicaSet, then how many replicas of this
            resource are available
            @see https://kubernetes.io/docs/concepts/workloads/controllers
            /replicaset/
            """
            return getattr(self, "_readyReplicas", None)

        @readyReplicas.setter
        def readyReplicas(self, rp: int):
            self._readyReplicas = rp

        @property
        def secondaryServiceEndpoint(self) -> str:
            """
            If this resource is a HA enabled, then show the secondary service
            endpoint
            """
            # if self._secondaryServiceEndpoint is None:
            #     return None
            # else:
            #     return self._secondaryServiceEndpoint
            return getattr(self, "_secondaryServiceEndpoint", None)

        @secondaryServiceEndpoint.setter
        def secondaryServiceEndpoint(self, se: str):
            self._secondaryServiceEndpoint = se

        @property
        def mirroringEndpoint(self) -> str:
            return getattr(self, "_mirroringEndpoint", None)

        @mirroringEndpoint.setter
        def mirroringEndpoint(self, me: str):
            self._mirroringEndpoint = me

        def _hydrate(self, d: dict):
            """
            @override
            """
            super()._hydrate(d)
            if "readyReplicas" in d:
                self.readyReplicas = d["readyReplicas"]
            if "secondaryServiceEndpoint" in d:
                self.secondaryServiceEndpoint = d["secondaryServiceEndpoint"]
            if "mirroringEndpoint" in d:
                self.mirroringEndpoint = d["mirroringEndpoint"]

        def _to_dict(self):
            """
            @override
            """
            base = super()._to_dict()
            base["readyReplicas"] = getattr(self, "readyReplicas", None)
            base["secondaryServiceEndpoint"] = getattr(
                self, "secondaryServiceEndpoint", None
            )
            base["mirroringEndpoint"] = getattr(self, "mirroringEndpoint", None)
            return base

    def _hydrate(self, d: dict):
        """
        @override
        """
        super()._hydrate(d)

    def _to_dict(self):
        """
        @override
        """
        return super()._to_dict()

    @validator
    def _validate_storage_classes(self, client: "KubernetesClient"):
        """
        Extends the super implementation of this to account for the datalogs
        volume
        @override CustomResource._validate_storage_classes
        """
        super()._validate_storage_classes(client)
        STORAGE_CLASS_ERROR = "Storage class '{}' does not exist"

        datalogs = getattr(self.spec.storage, "datalogs", None)
        if datalogs and datalogs.volumes:
            for v in datalogs.volumes:
                if v.className and not client.storage_class_exists(v.className):
                    raise ValueError(STORAGE_CLASS_ERROR.format(v.className))

    @validator
    def _validate_cores(self, client: "KubernetesClient"):
        """
        Verifies the cores request does not exceed the limit
        """
        # request = getattr(
        #     self.spec.scheduling.default.resources.requests, "cpu", None
        # )
        # lim = getattr(
        #     self.spec.scheduling.default.resources.limits, "cpu", None
        # )

        # # Lim and request could be empty strings if they're being deleted
        # # from the settings
        # if (
        #     lim
        #     and request
        #     and type(lim) is KubeQuantity
        #     and type(request) is KubeQuantity
        # ):
        #     if lim < request:
        #         raise ValueError(
        #             "CPU request of %s cannot exceed cores limit of %s"
        #             % (request.quantity, lim.quantity)
        #         )p
        pass

    @validator
    def _validate_memory(self, client: "KubernetesClient"):
        # """
        # verifies the memory request does not exceed the limit
        # """
        # request = getattr(
        #     self.spec.scheduling.default.resources.requests, "memory", None
        # )
        # lim = getattr(
        #     self.spec.scheduling.default.resources.limits, "memory", None
        # )

        # # Lim and request could be empty strings if they're being deleted
        # # from the settings
        # if (
        #     lim
        #     and request
        #     and type(lim) is KubeQuantity
        #     and type(request) is KubeQuantity
        # ):
        #     if request > lim:
        #         raise ValueError(
        #             "Memory request of %s cannot exceed memory limit of %s"
        #             % (request.quantity, lim.quantity)
        #         )s
        pass

    @validator
    def _validate_license_type(self, client: "KubernetesClient"):
        """
        Validates license type. Raise error if not valid.
        """
        if not validate_sqlmi_license_type(self.spec.license_type):
            raise ValueError(
                "Invalid license type: '{0}'. {1}".format(
                    self.spec.license_type,
                    SQLMI_LICENSE_TYPE_ALLOWED_VALUES_MSG,
                )
            )

    def apply_args(self, **kwargs):
        super().apply_args(**kwargs)
        self._set_if_provided(self.spec, "replicas", kwargs, "replicas")
        self._set_if_provided(
            self.spec.scheduling.default.resources.requests,
            "memory",
            kwargs,
            "memory_request",
        )
        self._set_if_provided(
            self.spec.scheduling.default.resources.requests,
            "cpu",
            kwargs,
            "cores_request",
        )
        self._set_if_provided(
            self.spec.scheduling.default.resources.limits,
            "memory",
            kwargs,
            "memory_limit",
        )
        self._set_if_provided(
            self.spec.scheduling.default.resources.limits,
            "cpu",
            kwargs,
            "cores_limit",
        )
        self._set_if_provided(self.spec, "tier", kwargs, "tier")
        self._set_if_provided(self.spec, "license_type", kwargs, "license_type")

        self._set_if_provided(
            self.spec.security, "adminLoginSecret", kwargs, "admin_login_secret"
        )
        self._set_if_provided(
            self.spec.security,
            "serviceCertificateSecret",
            kwargs,
            "service_certificate_secret",
        )

        key = "storage_class_datalogs"
        if key in kwargs and kwargs[key] is not None:
            if not self.spec.storage.datalogs.volumes:
                self.spec.storage.datalogs.volumes.append(VolumeClaim())
            self._set_if_provided(
                self.spec.storage.datalogs.volumes[0], "className", kwargs, key
            )

        key = "volume_size_datalogs"
        if key in kwargs and kwargs[key] is not None:
            if not self.spec.storage.datalogs.volumes:
                self.spec.storage.datalogs.volumes.append(VolumeClaim())
            self._set_if_provided(
                self.spec.storage.datalogs.volumes[0], "size", kwargs, key
            )

        if "labels" in kwargs and kwargs["labels"] is not None:
            labels = parse_labels(kwargs["labels"])
            setattr(self.metadata, "labels", labels)

        if "annotations" in kwargs and kwargs["annotations"] is not None:
            annotations = parse_labels(kwargs["annotations"])
            setattr(self.metadata, "annotations", annotations)

        if "service_labels" in kwargs and kwargs["service_labels"] is not None:
            labels = parse_labels(kwargs["service_labels"])
            setattr(self.spec.services.primary, "labels", labels)

        if (
            "service_annotations" in kwargs
            and kwargs["service_annotations"] is not None
        ):
            annotations = parse_labels(kwargs["service_annotations"])
            setattr(self.spec.services.primary, "annotations", annotations)

        if "storage_labels" in kwargs and kwargs["storage_labels"] is not None:
            labels = parse_labels(kwargs["storage_labels"])

            setattr(self.spec.storage.data.volumes[0], "labels", labels)
            setattr(self.spec.storage.logs.volumes[0], "labels", labels)

            if self.spec.storage.backups.volumes:
                setattr(self.spec.storage.backups.volumes[0], "labels", labels)

            if self.spec.storage.datalogs.volumes:
                setattr(self.spec.storage.datalogs.volumes[0], "labels", labels)

        if (
            "storage_annotations" in kwargs
            and kwargs["storage_annotations"] is not None
        ):
            annotations = parse_labels(kwargs["storage_annotations"])
            setattr(
                self.spec.storage.data.volumes[0], "annotations", annotations
            )
            setattr(
                self.spec.storage.logs.volumes[0], "annotations", annotations
            )

            if self.spec.storage.backups.volumes:
                setattr(
                    self.spec.storage.backups.volumes[0],
                    "annotations",
                    annotations,
                )

            if self.spec.storage.datalogs.volumes:
                setattr(
                    self.spec.storage.datalogs.volumes[0],
                    "annotations",
                    annotations,
                )

        # Construct SQL MI settings based on args
        #
        settings = self.spec.settings
        add_to_settings(settings, SQLMI_AGENT_ENABLED, kwargs, "agent_enabled")
        add_to_settings(settings, SQLMI_COLLATION, kwargs, "collation")
        add_to_settings(settings, SQLMI_LANGUAGE_LCID, kwargs, "language")
        add_to_settings(settings, SQLMI_TIMEZONE, kwargs, "time_zone")

        if "trace_flags" in kwargs and kwargs["trace_flags"] is not None:
            traceflags = parse_traceflags(kwargs["trace_flags"])
            settings[SQLMI_TRACEFLAGS] = traceflags

        setattr(self.spec, SQLMI_SETTINGS, settings)
