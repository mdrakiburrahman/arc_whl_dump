# ------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# ------------------------------------------------------------------------------

from azext_arcdata.kubernetes_sdk.models.dict_utils import SerializationUtils


class MonitoringSpec(SerializationUtils):
    """
    Monitoring spec for Data Controller custom resource
    """

    def __init__(
        self,
        enableKafka: bool = None,
    ):
        if enableKafka is not None:
            self.enableKafka = enableKafka

    @property
    def enableKafka(self) -> bool:
        return self._enableKafka

    @enableKafka.setter
    def enableKafka(self, enable: bool):
        self._enableKafka = enable

    def _to_dict(self) -> dict:
        return {
            "enableKafka": getattr(self, "enableKafka", None),
        }

    def _hydrate(self, d: dict):
        if "enableKafka" in d:
            self.enableKafka = d["enableKafka"]
