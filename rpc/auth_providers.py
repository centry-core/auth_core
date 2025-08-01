#!/usr/bin/python3
# coding=utf-8
# pylint: disable=C0115,C0116

#   Copyright 2025 getcarrier.io
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

""" RPC """

from pylon.core.tools import web, log  # pylint: disable=E0401,E0611,W0611

from ..tools import rpc_tools


class RPC:  # pylint: disable=R0903,E1101

    @web.rpc("auth_register_auth_provider", "register_auth_provider")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def register_auth_provider(  # pylint: disable=R0913,R0917
            self, name,
            login_route=None, login_url=None,
            logout_route=None, logout_url=None
    ):
        if name in self.auth_providers:
            raise ValueError(f"Provider is already registered: {name}")
        #
        self.auth_providers[name] = {
            "login_route": login_route,
            "login_url": login_url,
            "logout_route": logout_route,
            "logout_url": logout_url,
        }

    @web.rpc("auth_unregister_auth_provider", "unregister_auth_provider")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def unregister_auth_provider(self, name):
        if name not in self.auth_providers:
            raise ValueError(f"Provider is not registered: {name}")
        #
        self.auth_providers.pop(name)
