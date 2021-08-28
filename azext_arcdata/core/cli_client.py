# ------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# ------------------------------------------------------------------------------

"""
Client for all CLI actions.
"""

from azext_arcdata.kubernetes_sdk.client import KubernetesClient
from azext_arcdata.core.controller import ControllerClient
from azext_arcdata.core.output import OutputStream
from azext_arcdata.core.prompt import prompt
from azext_arcdata.core.util import is_windows, load_kube_config
from kubernetes.config.config_exception import ConfigException
from azure.cli.core._profile import Profile
from knack.cli import CLIError
from knack.log import get_logger
from knack.prompting import NoTTYException
from abc import ABCMeta
from six import add_metaclass

__all__ = ["client", "CliClient"]

logger = get_logger(__name__)


def beget_cli_client():
    """
    The factory function used to apply the common `CliClient` to a custom
    commands's command group.
    :return: A function.
    """

    def beget(_):
        return CliClient()

    return beget


client = beget_cli_client  # Export

# ============================================================================ #
# ============================================================================ #
# ============================================================================ #


@add_metaclass(ABCMeta)
class BaseCliClient(object):
    def __init__(self):
        pass

    @property
    def stdout(self):
        return OutputStream().stdout.write

    @property
    def stderr(self):
        return OutputStream().stderr.write

    @property
    def namespace(self):
        return self._namespace

    def __str__(self):
        """
        Returns the base string representation of attributes. Sub-class should
        override and implement.
        """
        return "<BaseCliClient>"

    def __repr__(self):
        """For `print` and `pprint`. Sub-class should override and implement."""
        return self.__str__()


# ============================================================================ #
# ============================================================================ #
# ============================================================================ #


class CliClient(BaseCliClient):
    """
    Default client injected in every command group. For further command
    customization extend this class.
    """

    def __init__(self, az_cli, namespace=None, check_namespace=True):
        super(CliClient, self).__init__()

        self._az_cli = az_cli
        self._utils = None
        self._terminal = None

        # -- exposed client APIS --
        self._apis = type("", (object,), {
            "kubernetes": KubernetesClient(),
            "controller": ControllerClient()
        })

        try:
            logger.debug("Provided k8s-namespace = {0}".format(namespace))
            logger.debug("Force namespace    = {0}".format(check_namespace))

            if not namespace and check_namespace:
                namespace = load_kube_config().get("namespace")
                if not namespace:
                    namespace = prompt("Kubernetes Namespace: ")
            self._namespace = namespace
            logger.debug(
                "Using Kubernetes namespace = {0}".format(self.namespace)
            )
        except NoTTYException:
            raise NoTTYException(
                "You must have a tty to prompt "
                "for Kubernetes namespace. Please provide a "
                "--k8s-namespace argument instead."
            )
        except (ConfigException, Exception) as ex:
            raise CLIError(ex)

    @property
    def az_cli(self):
        """
        Gets a reference to this command's `AzCli` execution context.
        """
        return self._az_cli

    @property
    def profile(self):
        """
        Gets the user Profile.
        :return:
        """
        return Profile(cli_ctx=self.az_cli.local_context.cli_ctx)

    @property
    def apis(self):
        """
        Gets the reference to the different API resource clients.
        """
        return self._apis

    @property
    def terminal(self):
        """
        Object mapping to supported public `terminal` operations.

         Supported:
        - `progress_indicator`

        Example:

        ```
        progress = client.terminal.progress_indicator
        ...
        ...
        ```

        :return: The Object mapping to supported terminal operations.
        """
        if self._terminal:
            return self._terminal

        # ----------------------------------------------------------------------
        # ----------------------------------------------------------------------
        # ----------------------------------------------------------------------

        class Progress(object):
            """
            Show a spinner on the terminal that automatically
            starts animating around a provided worker function.

            Example:

            ```
            add = lambda a, b: return a + b
            args = {'a': 1, 'b': 2}

            progress = client.terminal.progress_indicator
            result = progress.message('Downloading').worker(
            add, args).start()
            ```

            :return: A `Progress` instance to load-up and start.
            """

            def __init__(self):
                self._defaults()

            def _defaults(self):
                self._show_time = True
                self._worker = {"fn": None, "args": {}}
                self._message = ""

            def worker(self, fn, args):
                self._worker = {"fn": fn, "args": args}
                return self

            def message(self, message):
                self._message = message
                return self

            def show_time(self, show_time):
                self._show_time = show_time
                return self

            def start(self):
                from humanfriendly.terminal.spinners import AutomaticSpinner

                message = self._message
                worker_fn = self._worker.get("fn")
                arguments = self._worker.get("args")
                show_time = self._show_time

                assert worker_fn

                try:
                    if not is_windows():
                        with AutomaticSpinner(message, show_time=show_time):
                            return worker_fn(**arguments)
                    else:
                        # TODO: Make the same experience for windows ps1/dos
                        OutputStream().stdout.write(message)
                        result = worker_fn(**arguments)
                        return result
                finally:
                    self._defaults()  # reset

        # ----------------------------------------------------------------------
        # ----------------------------------------------------------------------
        # ----------------------------------------------------------------------
        from azext_arcdata.core.text import Text

        self._terminal = type(
            "", (object,), {"progress_indicator": Progress(), "text": Text()}
        )

        return self._terminal

    @property
    def utils(self):
        """
        Object mapping to supported public `utils` operations.

        Supported:
        - `download`
        - `import_api`

        Example:
        ```
        client.utils.download(...)
        client.utils.import_api(...)
        ```

        :return: The Object mapping to supported `utils` operations.
        """
        if self._utils:
            return self._utils

        # ----------------------------------------------------------------------
        # ----------------------------------------------------------------------
        # ----------------------------------------------------------------------

        def download(
            url,
            filename,
            destination=None,
            label="Downloading",
            show_progress=True,
        ):
            """
            Helper to download a file given the url and a write destination.
            If no
            destination is given the file download is sent to a temporary
            location.

            :param url: The URL to the file to be downloaded.
            :param filename: Name the downloaded file.
            :param destination: Location where to save file.
            :param label: Work with `show_progress` to define the label for the
                   optional spinner (a string or None, defaults to Downloading).
            :param show_progress: To display a progress spinner on the terminal.
            :return: The path to the downloaded file.
            """
            import urllib
            import time
            import tempfile
            import shutil
            import os

            def _download(uri, name, dest):
                stage_dir = tempfile.mkdtemp()
                try:
                    file_path = os.path.join(stage_dir, name)
                    num_blocks = 0
                    chunk_size = 4096
                    req = urllib.request.urlopen(uri)

                    with open(file_path, "wb") as f:
                        while True:
                            data = req.read(chunk_size)
                            time.sleep(0.5)
                            num_blocks += 1

                            if not data:
                                break

                            f.write(data)

                    return (
                        shutil.copyfile(file_path, dest) if dest else file_path
                    )
                except IsADirectoryError:
                    from urllib.error import URLError

                    raise URLError("Not able to download file", filename=uri)
                finally:
                    if dest:
                        shutil.rmtree(stage_dir, ignore_errors=True)

            if destination and not os.path.isdir(destination):
                raise ValueError(
                    "Destination directory does not exist {0}".format(
                        destination
                    )
                )

            # -- download and show progress indicator --
            if not show_progress:
                return _download(url, filename, destination)
            else:
                return (
                    self.terminal.progress_indicator.worker(
                        _download,
                        {"uri": url, "name": filename, "dest": destination},
                    )
                    .message(label)
                    .start()
                )

        # ----------------------------------------------------------------------
        # ----------------------------------------------------------------------
        # ----------------------------------------------------------------------

        self._utils = type("", (object,), {"download": download})

        return self._utils
