# ------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# ------------------------------------------------------------------------------

from azext_arcdata.kubernetes_sdk.models import (
    CustomResource,
    SerializationUtils,
)


class FogCustomResource(CustomResource):
    """
    Internal Sqlmi Custom Resource object to be used for deployments.
    """

    def __init__(
        self,
        spec: "FogCustomResource.Spec" = None,
        metadata: "FogCustomResource.Metadata" = None,
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

        def __init__(
            self,
            sharedName: str = None,
            sourceMI: str = None,
            partnerMI: str = None,
            partnerMirroringURL: str = None,
            partnerMirroringCert: str = None,
            role: str = None,
        ):
            super().__init__()
            self.sharedName = sharedName
            self.sourceMI = sourceMI
            self.partnerMI = partnerMI
            self.partnerMirroringURL = partnerMirroringURL
            self.partnerMirroringCert = partnerMirroringCert
            self.role = role

        @property
        def sharedName(self) -> str:
            return self._dagName

        @sharedName.setter
        def sharedName(self, dm: str):
            self._dagName = dm

        @property
        def sourceMI(self) -> str:
            return self._sourceMI

        @sourceMI.setter
        def sourceMI(self, nm: str):
            self._sourceMI = nm

        @property
        def partnerMI(self) -> str:
            return self._partnerMI

        @partnerMI.setter
        def partnerMI(self, rn: str):
            self._partnerMI = rn

        @property
        def partnerMirroringURL(self) -> str:
            return self._partnerMirroringURL

        @partnerMirroringURL.setter
        def partnerMirroringURL(self, re: str):
            self._partnerMirroringURL = re

        @property
        def partnerMirroringCert(self) -> str:
            return self._partnerMirroringCert

        @partnerMirroringCert.setter
        def partnerMirroringCert(self, rc: str):
            self._partnerMirroringCert = rc

        @property
        def role(self) -> str:
            return self._role

        @role.setter
        def role(self, r: str):
            self._role = r

        def _hydrate(self, d: dict):
            super()._hydrate(d)
            if "sharedName" in d:
                self.sharedName = d["sharedName"]
            if "sourceMI" in d:
                self.sourceMI = d["sourceMI"]
            if "partnerMI" in d:
                self.partnerMI = d["partnerMI"]
            if "partnerMirroringURL" in d:
                self.partnerMirroringURL = d["partnerMirroringURL"]
            if "partnerMirroringCert" in d:
                self.partnerMirroringCert = d["partnerMirroringCert"]
            if "role" in d:
                self.role = d["role"]

        def _to_dict(self) -> dict:
            base = super()._to_dict()
            base["sharedName"] = self.sharedName
            base["sourceMI"] = self.sourceMI
            base["partnerMI"] = self.partnerMI
            base["partnerMirroringURL"] = self.partnerMirroringURL
            base["partnerMirroringCert"] = self.partnerMirroringCert
            base["role"] = self.role
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
        def role(self) -> str:
            return self._role

        @role.setter
        def role(self, rp: str):
            self._role = rp

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
            if "role" in d:
                self.role = d["role"]
            if "results" in d:
                self.results = d["results"]

        def _to_dict(self):
            """
            @override
            """
            base = super()._to_dict()
            base["state"] = getattr(self, "state", None)
            base["role"] = getattr(self, "role", None)
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
