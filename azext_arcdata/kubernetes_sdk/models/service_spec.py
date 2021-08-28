# ------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# ------------------------------------------------------------------------------

from azext_arcdata.core.constants import (
    MAX_PORT_NUBMER,
    MIN_PORT_NUMBER,
    PORT_REQUIREMENTS,
)
from azext_arcdata.kubernetes_sdk.models.dict_utils import SerializationUtils


class ServiceSpec(SerializationUtils):
    """
    An internal representation of the service spec for a custom resource
    """

    def __init__(
        self,
        serviceType: str = None,
        port: int = None,
        labels: dict = None,
        annotations: dict = None,
    ):
        if port:
            self.port = port
        else:
            self._port = None

        if serviceType:
            self.serviceType = serviceType

        if labels:
            self.labels = labels

        if annotations:
            self.annotations = annotations

    @property
    def serviceType(self) -> str:
        return self._serviceType

    @serviceType.setter
    def serviceType(self, t: str):
        self._serviceType = t

    @property
    def port(self) -> str:
        return self._port

    @port.setter
    def port(self, p: str):
        try:
            val = int(p)
            if not MIN_PORT_NUMBER <= val <= MAX_PORT_NUBMER:
                raise ValueError(PORT_REQUIREMENTS)
        except ValueError:
            raise ValueError(PORT_REQUIREMENTS)
        except TypeError:
            raise ValueError(PORT_REQUIREMENTS)

        self._port = val

    @property
    def labels(self) -> dict:
        return self._labels

    @labels.setter
    def labels(self, l: dict):
        self._labels = l

    @property
    def annotations(self) -> dict:
        return self._annotations

    @annotations.setter
    def annotations(self, a: dict):
        self._annotations = a

    def _to_dict(self):
        """
        @override
        """
        return {
            "port": getattr(self, "port", None),
            "type": getattr(self, "serviceType", None),
            "labels": getattr(self, "labels", None),
            "annotations": getattr(self, "annotations", None),
        }

    def _hydrate(self, d: dict):
        """
        @override
        """
        if "port" in d:
            self.port = d["port"]

        if "type" in d:
            self.serviceType = d["type"]

        if "labels" in d:
            self.labels = d["labels"]

        if "annotations" in d:
            self.annotations = d["annotations"]
