from collections import OrderedDict
from jmespath import compile as compile_jmes, Options  # pylint: disable=import-error


def customlocation_show_table_format(result):
    """Format a customlocation as summary results for display with "-o table"."""
    return [_customlocation_table_format(result)]


def customlocation_list_table_format(results):
    """Format a customlocation list for display with "-o table"."""
    return [_customlocation_list_table_format(r) for r in results]


def _customlocation_table_format(result):
    parsed = compile_jmes("""{
        name: name,
        location: location,
        resourceGroup: resourceGroup,
        namespace: namespace,
        provisioningState: provisioningState
    }""")
    # use ordered dicts so headers are predictable
    return parsed.search(result, Options(dict_cls=OrderedDict))


def _customlocation_list_table_format(result):
    parsed = compile_jmes("""{
        name: name,
        location: location,
        resourceGroup: resourceGroup,
        namespace: namespace,
        provisioningState: provisioningState
    }""")
    # use ordered dicts so headers are predictable
    return parsed.search(result, Options(dict_cls=OrderedDict))
