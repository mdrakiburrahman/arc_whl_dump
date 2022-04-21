# ------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# ------------------------------------------------------------------------------

from types import SimpleNamespace
from typing import Callable
from json import JSONEncoder, dumps, loads

import time
import pydash as _


def dict_to_dot_notation(d: dict):
    class _Namespace(SimpleNamespace):
        @property
        def to_dict(self):
            class _Encoder(JSONEncoder):
                def default(self, o):
                    return o.__dict__

            return loads(dumps(self, indent=4, cls=_Encoder))

    return loads(dumps(d), object_hook=lambda item: _Namespace(**item))


def wait_for_error(
    func: Callable, *func_args, retry_tol=1800, retry_delay=5, e=Exception
):
    for _ in range(0, retry_tol, retry_delay):
        try:
            func(*func_args)
            time.sleep(retry_delay)
        except e:
            break


def wait(func: Callable, *func_args, retry_tol=1800, retry_delay=5):
    try:
        current_status = None
        for _ in range(0, retry_tol, retry_delay):
            status = func(*func_args)
            if status == "Ready":
                break
            elif status and "Error" in status:
                raise Exception(
                    f"An error happened while waiting. The "
                    f"deployment state is: \n{status}"
                )
            else:
                if current_status != status:
                    if current_status:
                        print(
                            f"Deployment state '{current_status}' "
                            f"has completed."
                        )

                    current_status = status
                    print(f"Current deployment state is '{current_status}'")

                time.sleep(retry_delay)
    except Exception as e:
        raise e


def retry(func: Callable, *func_args, max_tries=10, retry_delay=5, e=Exception):
    for i in range(max_tries):
        try:
            time.sleep(retry_delay)
            result = func(*func_args)
            break
        except e:
            continue
    return result
