# ------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# ------------------------------------------------------------------------------

from azure.identity._internal.get_token_mixin import GetTokenMixin
from azure.cli.core._profile import Profile
from azure.cli.core._session import ACCOUNT
from azure.cli.core._environment import get_config_dir
from knack.log import get_logger

import os
import time

__all__ = ["ArcDataCliCredential"]

logger = get_logger(__name__)


class ArcDataCliCredential(GetTokenMixin):
    def __init__(self, scopes=None):
        super(ArcDataCliCredential, self).__init__()
        self._scopes = scopes

    # override
    def _acquire_token_silently(self, *scopes):
        # type: (*str) -> Optional[AccessToken]
        """
        Attempt to acquire an access token from a cache or by redeeming
        a refresh token
        """
        azure_folder = get_config_dir()
        ACCOUNT.load(os.path.join(azure_folder, "azureProfile.json"))
        p = Profile(storage=ACCOUNT)
        cred, subscription_id, tenant_id = p.get_login_credentials()
        access_token = cred.get_token(*scopes)

        return access_token

    # override
    def get_token(self, *scopes, **kwargs):
        # type: (*str, **Any) -> AccessToken
        """
        Request an access token for `scopes`.
        """
        # if not scopes:
        #    scopes = self._scopes

        try:
            token = self._acquire_token_silently(*scopes)
            if not token:
                self._last_request_time = int(time.time())
                token = self._request_token(*scopes)
            elif self._should_refresh(token):
                try:
                    self._last_request_time = int(time.time())
                    token = self._request_token(*scopes, **kwargs)
                except Exception:  # pylint:disable=broad-except
                    pass
            logger.debug("%s.get_token succeeded", self.__class__.__name__)
            return token

        except Exception as ex:
            logger.debug("%s.get_token: %s", self.__class__.__name__, ex)
            raise

    # override
    def _request_token(self, *scopes, **kwargs):
        # TODO
        pass
