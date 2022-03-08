# ------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# ------------------------------------------------------------------------------


from types import SimpleNamespace
from json import JSONEncoder, dumps, loads


def dict_to_dot_notation(d: dict):
    class _Namespace(SimpleNamespace):
        @property
        def to_dict(self):
            class _Encoder(JSONEncoder):
                def default(self, o):
                    return o.__dict__

            return loads(dumps(self, indent=4, cls=_Encoder))

    return loads(dumps(d), object_hook=lambda item: _Namespace(**item))
