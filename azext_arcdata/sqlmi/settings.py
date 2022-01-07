# ------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# ------------------------------------------------------------------------------


def parse_traceflags(tf_str: str):
    """
    Parses the traceflags str to generate a list of traceflags.
    """
    traceflags = []
    tfs_split = tf_str.split(",")

    for tf_raw in tfs_split:

        if not tf_raw.isdigit():
            raise ValueError(
                "Traceflags must be list of integers separated by ','."
            )

        if tf_raw in traceflags:
            raise ValueError(
                "Duplicate traceflag '{}' specified.".format(tf_raw)
            )

        traceflags.append(tf_raw.strip())

    return traceflags


def add_to_settings(settings, key, kwargs, arg_key):
    """
    Adds the key to settings from kwargs.
    """
    if settings is None:
        settings = {}

    if arg_key in kwargs and kwargs[arg_key] is not None:
        setting_keys = key.split(".")

        # Unflatten the settings dictionary by going through split keys in
        # reverse and add to settings
        #
        s_val = kwargs[arg_key]
        for i in range(len(setting_keys) - 1, 0, -1):
            s = {setting_keys[i]: s_val}
            s_val = s

        settings[setting_keys[0]] = s_val
