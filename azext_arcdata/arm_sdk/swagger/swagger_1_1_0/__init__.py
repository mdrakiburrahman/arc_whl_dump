# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator (autorest: 3.8.3, generator: @autorest/python@5.16.0)
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from ._azure_arc_data_management_client import AzureArcDataManagementClient
from ._version import VERSION

__version__ = VERSION

try:
    from ._patch import __all__ as _patch_all
    from ._patch import *  # type: ignore # pylint: disable=unused-wildcard-import
except ImportError:
    _patch_all = []
from ._patch import patch_sdk as _patch_sdk

__all__ = ["AzureArcDataManagementClient"]
__all__.extend([p for p in _patch_all if p not in __all__])

_patch_sdk()
