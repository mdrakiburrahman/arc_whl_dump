# ------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# -----------------------------------------------------------------------------

import re
from decimal import Decimal
from typing import Union
from copy import deepcopy
from knack.cli import CLIError
from azext_arcdata.kubernetes_sdk.models.custom_resource import CustomResource
from azext_arcdata.postgres.constants import (
    POSTGRES_MIN_CORES_SIZE,
    POSTGRES_MIN_MEMORY_SIZE,
)
from azext_arcdata.kubernetes_sdk.models.dict_utils import SerializationUtils
from azext_arcdata.core.constants import DNS_NAME_REQUIREMENTS
from azext_arcdata.kubernetes_sdk.models.kube_quantity import KubeQuantity
from azext_arcdata.core.util import name_meets_dns_requirements
from azext_arcdata.postgres.constants import (
    RESOURCE_KIND,
    SUPPORTED_ENGINE_VERSIONS,
    DEFAULT_ENGINE_VERSION,
)
from azext_arcdata.core.class_utils import validator, validatedclass
from typing import TYPE_CHECKING

# KubernetesClient is only needed for typehints, but causes a circular import. This is the python provided workaround
if TYPE_CHECKING:
    from azext_arcdata.kubernetes_sdk.client import KubernetesClient


@validatedclass
class PostgresqlCustomResource(CustomResource):
    """
    Internal Postgres Custom Resource object to be used for deployments.
    """

    def __init__(self):
        super().__init__()

    class Spec(CustomResource.Spec):
        """
        CustomResource.spec
        @override
        """

        def __init__(self):
            super().__init__()
            self.scheduling = self.Scheduling()
            self.engine = self.Engine()
            self.scale = self.Scale()

        class Engine(SerializationUtils):
            """
            CustomResource.spec.engine
            """

            def __init__(self):
                self.extensions = []
                # Need to initialize directly rather than going through setter, since setting this value typically
                # uses the existing value
                self._version = DEFAULT_ENGINE_VERSION
                self._settings = {"roles": {}, "default": {}}

            @property
            def version(self) -> int:
                """
                PostgreSQL engine version
                """
                return self._version

            @version.setter
            def version(self, v: int):
                self._version = v

            @property
            def extensions(self) -> list:
                return self._extensions

            @extensions.setter
            def extensions(self, e: Union[list, str]):
                if type(e) is str:
                    self._extensions = self._parse_engine_extensions_string(e)
                elif type(e) is list:
                    self._extensions = e
                else:
                    raise ValueError(
                        "Type '{}' is not compatible with property 'extentions'. Need 'str', or 'list'".format(
                            type(e)
                        )
                    )

            @property
            def settings(self) -> dict:
                return self._settings

            @settings.setter
            def settings(self, s: dict):
                self.set_engine_settings(s, overwrite=True)

            def _insert_settings_per_role(
                self,
                engine_settings,
                role_key="default",
                replace_engine_settings=False,
            ):
                original_settings = (
                    self._settings["default"]
                    if role_key == "default"
                    else self._settings["roles"].get(role_key, {})
                )
                new_settings = self._get_new_engine_settings(
                    engine_settings, replace_engine_settings, role_key
                )

                if new_settings != original_settings:
                    if role_key == "default":
                        self._settings["default"] = new_settings
                    else:
                        self._settings["roles"][role_key] = new_settings

            def set_engine_settings(self, s: dict, overwrite=False):
                """
                Sets the engine settings from a dictionary by calling set_engine_settings_per_role()
                :param s: the new settings. If s doesnt contain "roles", set_engine_settings_per_role
                is called with 'default' role.
                :param overwrite: overwrite flag is passed to set_engine_settings_per_role
                """
                if "default" in s:
                    self.set_engine_settings_per_role(s, "default", overwrite)
                if "roles" in s and s["roles"] is not None:
                    for role_key in s["roles"].keys():
                        self.set_engine_settings_per_role(
                            s, role_key, overwrite
                        )

            def set_engine_settings_per_role(
                self, s: Union[str, dict], role="default", overwrite=False
            ):
                """
                Sets the engine settings from either a settings string or a dictionary, and optionally overwrites the
                existing settings completely. (Merges settings by default)
                :param s: the new settings
                :param role: node role
                :param overwrite: False by default. If True eliminates all existing settings before replacing them, if
                False this function retains existing settings and will overwrite or add any provided keys where appropriate
                """
                if type(s) is str:
                    self._insert_settings_per_role(
                        self._parse_engine_settings_string(s), role, overwrite
                    )
                elif type(s) is dict:
                    # If default or specified role exists under settings.roles or settings, then pass <default/node role>.items() to
                    # _insert_settings_per_role(), If default/ specified role do not persist in the spec or the role
                    # is different or empty pass parent level .items()
                    if role == "default":
                        self._insert_settings_per_role(
                            s["default"].items()
                            if "default" in s
                            else s.items(),
                            "default",
                            overwrite,
                        )
                    elif "roles" in s:
                        self._insert_settings_per_role(
                            s["roles"][role].items()
                            if role in s["roles"]
                            else s["roles"].items(),
                            role,
                            overwrite,
                        )
                else:
                    raise TypeError(
                        "Invalid type '{}' for CustomResource.engine.settings. valid types are 'str' and 'dict'".format(
                            type(s)
                        )
                    )

            def _get_new_engine_settings(
                self,
                engine_settings,
                overwrite_engine_settings: bool,
                role="default",
            ):
                """
                Computes new engine settings based on the provided engine settings, the existing settings, and the overwrite
                flag. Note: Does NOT mutate the underlying dictionary
                :param engine_settings: the settings that are being provided
                :param overwrite_engine_settings: If True existing settings are wiped out, if False they are retained and
                overridden where appropriate
                :returns: A dictionary with what the new settings would be based on the provided settings and the overwrite
                flag.
                """
                if role == "default":
                    base_settings = (
                        self.settings["default"]
                        if not overwrite_engine_settings
                        else {}
                    )
                else:
                    base_settings = (
                        self.settings["roles"].get(role, {})
                        if not overwrite_engine_settings
                        else {}
                    )
                # Must be careful to avoid mutating underlying dict or this method could cause undocumented side effects
                #
                new_settings = base_settings.copy()
                for k, v in engine_settings:
                    if not v:
                        new_settings[k] = None
                    else:
                        new_settings[k] = v
                for k in list(new_settings.keys()):
                    if new_settings[k] is None:
                        del new_settings[k]

                return new_settings

            @staticmethod
            def _parse_engine_settings_string(engine_settings: str):
                """
                Given a settings string in format "key=val,key2=val2,..." returns the settings as a list of tuples of
                the form [(key, val),(key2, val2),...]
                :returns: A list of tuples representing the provided settings string
                """
                return re.findall(
                    r'\s*([^\s=,]+)\s*=\s*("(?:[^"]|"")*"|[^\s",]*),?',
                    engine_settings.replace("'", "").replace('"', ""),
                )

            @staticmethod
            def _parse_engine_extensions_string(extensions: str):
                return [
                    e.strip()
                    for e in extensions.replace('"', "").strip().split(",")
                ]

            def _to_dict(self) -> dict:
                return {
                    "version": self.version,
                    "extensions": [{"name": e} for e in self.extensions],
                    "settings": self.settings,
                }

            def _hydrate(self, d: dict):
                if "extensions" in d:
                    exts = d["extensions"]
                    if (
                        type(exts) is list
                        and len(exts) > 0
                        and type(exts[0]) is dict
                    ):
                        self.extensions = [e["name"] for e in exts]
                    else:
                        self.extensions = d["extensions"]

                if "settings" in d:
                    self.settings = d["settings"]

                if "version" in d:
                    self.version = d["version"]

        @property
        def engine(self) -> Engine:
            return self._engine

        @engine.setter
        def engine(self, e: Engine):
            self._engine = e

        class Scheduling(SerializationUtils):
            """
            CustomResource.spec.scheduling
            """

            def __init__(self):
                # If you add a nested class, please create a property and initialize it here
                #
                self.roles = self.Roles()
                self.default = self.Default(self.roles.Resources())

            class Roles(SerializationUtils):
                """
                CustomResource.spec.scheduling.roles
                """

                def __init__(self):
                    self._monitor = self.Role(self.Resources())
                    self._proxy = self.Role(self.Resources())
                    self._coordinator = self.Role(self.Resources())
                    self._worker = self.Role(self.Resources())

                class Role(SerializationUtils):
                    def __init__(self, resources):
                        self._resources = deepcopy(resources)

                    @property
                    def resources(self):
                        return self._resources

                    @resources.setter
                    def resources(self, r):
                        self._resources = r

                    def _to_dict(self) -> dict:
                        return {"resources": self._resources._to_dict()}

                    def _hydrate(self, d: dict):
                        if "resources" in d:
                            self.resources._hydrate(d["resources"])

                @property
                def coordinator(self):
                    return self._coordinator

                @coordinator.setter
                def coordinator(self, r: Role):
                    self._coordinator = r

                @property
                def worker(self):
                    return self._worker

                @worker.setter
                def worker(self, s: Role):
                    self._worker = s

                @property
                def proxy(self):
                    return self._proxy

                @proxy.setter
                def proxy(self, s: Role):
                    self._proxy = s

                @property
                def monitor(self):
                    return self._monitor

                @monitor.setter
                def monitor(self, s: Role):
                    self._monitor = s

                def _hydrate(self, d: dict):
                    if "monitor" in d:
                        self.monitor._hydrate(d["monitor"])
                    if "proxy" in d:
                        self.proxy._hydrate(d["proxy"])
                    if "coordinator" in d:
                        self.coordinator._hydrate(d["coordinator"])
                    if "worker" in d:
                        self.worker._hydrate(d["worker"])

                class Resources(SerializationUtils):
                    """
                    CustomResource.spec.scheduling.roles.resources
                    """

                    def __init__(self):
                        self.requests = self.Requests()
                        self.limits = self.Limits()

                    class Requests(SerializationUtils):
                        """
                        CustomResource.spec.scheduling.default.resources.requests
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
                            if val < POSTGRES_MIN_MEMORY_SIZE:
                                raise ValueError(
                                    "Postgres memory request must be at least '{}'".format(
                                        POSTGRES_MIN_MEMORY_SIZE.quantity
                                    )
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
                            if val < POSTGRES_MIN_CORES_SIZE:
                                raise ValueError(
                                    "Postgres cores request must be at least '{}'".format(
                                        POSTGRES_MIN_CORES_SIZE.quantity
                                    )
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
                            if val < POSTGRES_MIN_MEMORY_SIZE:
                                raise ValueError(
                                    "Postgres memory limit must be at least '{}'".format(
                                        POSTGRES_MIN_MEMORY_SIZE.quantity
                                    )
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
                            if val < POSTGRES_MIN_CORES_SIZE:
                                raise ValueError(
                                    "Postgres memory limit must be at least '{}'".format(
                                        POSTGRES_MIN_CORES_SIZE.quantity
                                    )
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

                def _to_dict(self) -> dict:
                    return {
                        "monitor": self.monitor._to_dict(),
                        "proxy": self.proxy._to_dict(),
                        "coordinator": self.coordinator._to_dict(),
                        "worker": self.worker._to_dict(),
                    }

            @property
            def roles(self) -> Roles:
                return self._roles

            @roles.setter
            def roles(self, r: Roles):
                self._roles = r

            def _to_dict(self) -> dict:
                return {
                    "roles": self.roles._to_dict(),
                    "default": self.default._to_dict(),
                }

            def _hydrate(self, d: dict):
                if "roles" in d:
                    self.roles._hydrate(d["roles"])
                if "default" in d:
                    self.default._hydrate(d["default"])

            class Default(SerializationUtils):
                def __init__(self, resources):
                    self._resources = deepcopy(resources)

                @property
                def resources(self):
                    return self._resources

                @resources.setter
                def resources(self, r):
                    self._resources = r

                def _to_dict(self) -> dict:
                    return {"resources": self._resources._to_dict()}

                def _hydrate(self, d: dict):
                    if "resources" in d:
                        self.resources._hydrate(d["resources"])

            @property
            def default(self):
                return self._default

            @default.setter
            def default(self, s: Default):
                self._default = s

        @property
        def scheduling(self) -> Scheduling:
            return self._scheduling

        @scheduling.setter
        def scheduling(self, s: Scheduling):
            self._scheduling = s

        @property
        def scheduling(self) -> Scheduling:
            return self._scheduling

        @scheduling.setter
        def scheduling(self, s: Scheduling):
            self._scheduling = s

        class Scale(SerializationUtils):
            """
            Namespaces custom resource spec properties relating to how resources should scale

            CustomResource.spec.scale
            """

            def __init__(self, shards: int = None, replicas: int = 1):
                self._shards = shards
                self._replicas = replicas

            @property
            def shards(self) -> int:
                """
                A database custom resource property - How many partitions a table should be spread out across
                """
                return self._shards

            @property
            def replicas(self) -> int:
                """
                A database custom resource property - How many replicas of the postgres server to be deployed
                """
                return self._replicas

            @shards.setter
            def shards(self, s: Union[int, str]):
                self._shards = int(s)

            @replicas.setter
            def replicas(self, s: Union[int, str]):
                self._replicas = int(s)

            def _hydrate(self, d: dict):
                """
                @override
                """
                if "workers" in d:
                    self.shards = d["workers"]
                if "replicas" in d:
                    self.replicas = d["replicas"]

            def _to_dict(self):
                """
                @override
                """
                return {
                    "workers": self.shards,
                    "replicas": self.replicas,
                }

        @property
        def scale(self) -> Scale:
            return self._scale

        @scale.setter
        def scale(self, s: Scale):
            self._scale = s

        def _to_dict(self) -> dict:
            base = super()._to_dict()
            base["engine"] = self.engine._to_dict()
            base["scheduling"] = self.scheduling._to_dict()
            base["scale"] = self.scale._to_dict()
            return base

        def _hydrate(self, d: dict):
            super()._hydrate(d)
            if "engine" in d:
                self.engine._hydrate(d["engine"])

            if "scheduling" in d:
                self.scheduling._hydrate(d["scheduling"])

            if "scale" in d:
                self.scale._hydrate(d["scale"])

    class Metadata(CustomResource.Metadata):
        """
        CustomResource.metadata
        @override
        """

        arc_psql_name_max_length = 10

        @CustomResource.Metadata.name.setter
        def name(self, n: str):
            if not n:
                raise ValueError(
                    "Azure Arc enabled PostgreSQL Hyperscale server group name cannot be empty"
                )

            if len(n) > self.arc_psql_name_max_length:
                raise ValueError(
                    "Azure Arc enabled PostgreSQL Hyperscale server group name '{}' exceeds {} character length limit".format(
                        n, self.arc_psql_name_max_length
                    )
                )

            if not name_meets_dns_requirements(n):
                raise ValueError(
                    "Azure Arc enabled PostgreSQL Hyperscale server group name '{}' does not follow DNS requirements: {}".format(
                        n, DNS_NAME_REQUIREMENTS
                    )
                )

            if not name_meets_dns_requirements(n):
                raise ValueError(
                    "Postgres server name '{}' does not follow DNS requirements: {}".format(
                        n, DNS_NAME_REQUIREMENTS
                    )
                )

            self._name = n

    class Status(CustomResource.Status):
        """
        @override CustomResource.Status
        """

        def __init__(self):
            super().__init__()

        @property
        def readyPods(self) -> int:
            return self._readyPods

        @readyPods.setter
        def readyPods(self, rp: int):
            self._readyPods = rp

        def _hydrate(self, d: dict):
            """
            @override
            """
            super()._hydrate(d)
            if "readyPods" in d:
                self.readyPods = d["readyPods"]

        def _to_dict(self):
            """
            @override
            """
            base = super()._to_dict()
            base["readyPods"] = getattr(self, "readyPods", None)
            return base

    def _insert_property_value(self, node_role, property_str, value, input_str):
        role = (
            getattr(self.spec.scheduling, node_role, None)
            if node_role == "default"
            else getattr(self.spec.scheduling.roles, node_role, None)
        )
        if value is not None and role:
            if "limit" in input_str:
                setattr(role.resources.limits, property_str, value)
            if "request" in input_str:
                setattr(role.resources.requests, property_str, value)

    def apply_args(self, replace_engine_settings=False, **kwargs):
        super().apply_args(**kwargs)
        if kwargs["memory_request"] is not None:
            if "=" not in kwargs["memory_request"]:
                self._insert_property_value(
                    "default",
                    "memory",
                    kwargs["memory_request"],
                    "memory_request",
                )
            else:
                for pair in self._parse_roles(kwargs["memory_request"]):
                    self._insert_property_value(
                        self._to_role(pair[0]),
                        "memory",
                        pair[1],
                        "memory_request",
                    )
        if kwargs["cores_request"] is not None:
            if "=" not in kwargs["cores_request"]:
                self._insert_property_value(
                    "default", "cpu", kwargs["cores_request"], "cores_request"
                )
            else:
                for pair in self._parse_roles(kwargs["cores_request"]):
                    self._insert_property_value(
                        self._to_role(pair[0]), "cpu", pair[1], "cores_request"
                    )
        if kwargs["memory_limit"] is not None:
            if "=" not in kwargs["memory_limit"]:
                self._insert_property_value(
                    "default", "memory", kwargs["memory_limit"], "memory_limit"
                )
            else:
                for pair in self._parse_roles(kwargs["memory_limit"]):
                    self._insert_property_value(
                        self._to_role(pair[0]),
                        "memory",
                        pair[1],
                        "memory_limit",
                    )
        if kwargs["cores_limit"] is not None:
            if "=" not in kwargs["cores_limit"]:
                self._insert_property_value(
                    "default", "cpu", kwargs["cores_limit"], "cores_limit"
                )
            else:
                for pair in self._parse_roles(kwargs["cores_limit"]):
                    self._insert_property_value(
                        self._to_role(pair[0]), "cpu", pair[1], "cores_limit"
                    )

        if "engine_version" in kwargs:
            engine_version = kwargs["engine_version"]
            if engine_version not in SUPPORTED_ENGINE_VERSIONS:
                raise ValueError(
                    "Unsupported engine version '{}'".format(engine_version)
                )
            self.spec.engine.version = engine_version
        self.kind = RESOURCE_KIND

        self._set_if_provided(self.spec.scale, "shards", kwargs, "workers")
        self._set_if_provided(self.spec.scale, "replicas", kwargs, "replicas")
        self._set_if_provided(
            self.spec.engine, "extensions", kwargs, "extensions"
        )
        if (
            "engine_settings" in kwargs
            and kwargs["engine_settings"] is not None
        ):
            self.spec.engine.set_engine_settings_per_role(
                kwargs["engine_settings"], "default", replace_engine_settings
            )
        if (
            "coordinator_engine_settings" in kwargs
            and kwargs["coordinator_engine_settings"] is not None
        ):
            self.spec.engine.set_engine_settings_per_role(
                kwargs["coordinator_engine_settings"],
                "coordinator",
                replace_engine_settings,
            )
        if (
            "worker_engine_settings" in kwargs
            and kwargs["worker_engine_settings"] is not None
        ):
            self.spec.engine.set_engine_settings_per_role(
                kwargs["worker_engine_settings"],
                "worker",
                replace_engine_settings,
            )

    def _to_dict(self) -> dict:
        return super()._to_dict()

    def _hydrate(self, d: dict):
        super()._hydrate(d)

    @validator
    def _validate_cores(self, client: "KubernetesClient"):
        """
        Verifies the cores request does not exceed the limit
        """
        request = getattr(
            self.spec.scheduling.default.resources.requests, "cpu", None
        )
        lim = getattr(
            self.spec.scheduling.default.resources.limits, "cpu", None
        )

        # Lim and request could be empty strings if they're being deleted from the settings
        if (
            lim
            and request
            and type(lim) is KubeQuantity
            and type(request) is KubeQuantity
        ):
            if lim < request:
                raise ValueError(
                    "Cores request of %s cannot exceed cores limit of %s"
                    % (request.quantity, lim.quantity)
                )

    @validator
    def _validate_memory(self, client: "KubernetesClient"):
        """
        verifies the memory request does not exceed the limit
        """
        request = getattr(
            self.spec.scheduling.default.resources.requests, "memory", None
        )
        lim = getattr(
            self.spec.scheduling.default.resources.limits, "memory", None
        )

        # Lim and request could be empty strings if they're being deleted from the settings
        if (
            lim
            and request
            and type(lim) is KubeQuantity
            and type(request) is KubeQuantity
        ):
            if request > lim:
                raise ValueError(
                    "Memory request of %s cannot exceed memory limit of %s"
                    % (request.quantity, lim.quantity)
                )

    @staticmethod
    def get_resource_kind_by_engine_version(engine_version: int):
        """
        Returns the resource kind defined in the corresponding CRD for the specified postgresql engine version.
        :param engine_version: The postgresql engine version.
        :return:
        """
        kind = ENGINE_VERSION_TO_KIND.get(engine_version)
        if not kind:
            raise CLIError(
                "Unsupported engine version {}".format(engine_version)
            )
        return kind

    @staticmethod
    def _to_role(role):
        switcher = {
            "c": "coordinator",
            "w": "worker",
            "m": "monitor",
            "coordinator": "coordinator",
            "worker": "worker",
            "default": "default",
        }
        role = switcher.get(role.lower())
        if role is None:
            raise ValueError("Invalid value passed for role to map.")
        return role

    @staticmethod
    def _get_roles():
        return ["monitor", "worker", "coordinator", "default", "c", "w", "m"]

    @staticmethod
    def _parse_roles(values):
        pairs = [v.strip().split("=") for v in values.split(",")]
        for role in pairs:
            if not role[0].lower() in PostgresqlCustomResource._get_roles():
                raise ValueError(
                    "Roles provided are not valid. Valid role values are "
                    + ", ".join(PostgresqlCustomResource._get_roles())
                    + "."
                )
        return pairs
