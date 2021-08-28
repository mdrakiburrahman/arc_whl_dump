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


class DagCustomResource(CustomResource):
    """
    Internal Sqlmi Custom Resource object to be used for deployments.
    """

    def __init__(
        self,
        spec: "DagCustomResource.Spec" = None,
        metadata: "DagCustomResource.Metadata" = None,
    ):
        """
        Initializes a CR object with the given json.
        """
        super().__init__()
        self.spec = spec if spec else self.Spec()
        self.metadata = metadata if metadata else self.Metadata()

    class Spec(CustomResource.Spec):
        """
        @override CustomResource.spec
        """

        def __init__(self, input: "DagCustomResource.Spec.Input" = None):
            super().__init__()
            self.input = input if input else self.Input()

        class Input(SerializationUtils):
            def __init__(
                self,
                dagName: str = None,
                localName: str = None,
                remoteName: str = None,
                remoteEndpoint: str = None,
                remotePublicCert: str = None,
                isLocalPrimary: bool = None,
            ):

                self.dagName = dagName
                self.localName = localName
                self.remoteName = remoteName
                self.remoteEndpoint = remoteEndpoint
                self.remotePublicCert = remotePublicCert
                self.isLocalPrimary = isLocalPrimary

            @property
            def dagName(self) -> str:
                return self._dagName

            @dagName.setter
            def dagName(self, dm: str):
                self._dagName = dm

            @property
            def localName(self) -> str:
                return self._localName

            @localName.setter
            def localName(self, nm: str):
                self._localName = nm

            @property
            def remoteName(self) -> str:
                return self._remoteName

            @remoteName.setter
            def remoteName(self, rn: str):
                self._remoteName = rn

            @property
            def remoteEndpoint(self) -> str:
                return self._remoteEndpoint

            @remoteEndpoint.setter
            def remoteEndpoint(self, re: str):
                self._remoteEndpoint = re

            @property
            def remotePublicCert(self) -> str:
                return self._remoteCertHexEncoded

            @remotePublicCert.setter
            def remotePublicCert(self, rc: str):
                self._remoteCertHexEncoded = rc

            @property
            def isLocalPrimary(self) -> bool:
                return self._isLocalPrimary

            @isLocalPrimary.setter
            def isLocalPrimary(self, ip: bool):
                self._isLocalPrimary = ip

            def _hydrate(self, d: dict):
                if "dagName" in d:
                    self.dagName = d["dagName"]
                if "localName" in d:
                    self.localName = d["localName"]
                if "remoteName" in d:
                    self.remoteName = d["remoteName"]
                if "remoteEndpoint" in d:
                    self.remoteEndpoint = d["remoteEndpoint"]
                if "remotePublicCert" in d:
                    self.remotePublicCert = d["remotePublicCert"]
                if "isLocalPrimary" in d:
                    self.isLocalPrimary = d["isLocalPrimary"]

            def _to_dict(self) -> dict:
                return {
                    "dagName": self.dagName,
                    "localName": self.localName,
                    "remoteName": self.remoteName,
                    "remoteEndpoint": self.remoteEndpoint,
                    "remotePublicCert": self.remotePublicCert,
                    "isLocalPrimary": self.isLocalPrimary,
                }

        @property
        def input(self) -> Input:
            return self._input

        @input.setter
        def input(self, ip: Input):
            self._input = ip

        def _hydrate(self, d: dict):
            super()._hydrate(d)
            if "input" in d:
                self.input._hydrate(d["input"])

        def _to_dict(self):
            base = super()._to_dict()
            base["input"] = self.input._to_dict()
            return base

    class Metadata(CustomResource.Metadata):
        """
        @override CustomResource.metadata
        """

        def __init__(self, name: str = None):
            super().__init__()

        @CustomResource.Metadata.name.setter
        def name(self, n: str):
            """
            @override CustomResource.metadata.name.setter
            """
            if not n:
                raise ValueError("Rest API name cannot be empty")

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
        def state(self) -> str:
            return self._state

        @state.setter
        def state(self, rp: str):
            self._state = rp

        @property
        def results(self) -> str:
            return self._results

        @results.setter
        def results(self, se: str):
            self._results = se

        def _hydrate(self, d: dict):
            """
            @override
            """
            super()._hydrate(d)
            if "state" in d:
                self.state = d["state"]
            if "results" in d:
                self.results = d["results"]

        def _to_dict(self):
            """
            @override
            """
            base = super()._to_dict()
            base["state"] = getattr(self, "state", None)
            base["results"] = getattr(self, "results", None)
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

    def apply_args(self, **kwargs):
        super().apply_args(**kwargs)
