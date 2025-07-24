#!/usr/bin/python3
# coding=utf-8
# pylint: disable=C0116,W0201

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

""" Method """

from pylon.core.tools import web, log  # pylint: disable=E0401,E0611,W0611


class Method:  # pylint: disable=E1101,R0903
    """
        Method Resource

        self is pointing to current Module instance

        web.method decorator takes zero or one argument: method name
        Note: web.method decorator must be the last decorator (at top)

    """

    @web.init()
    def success_mappers_init(self):
        self.success_mappers = {}  # target -> rpc_endpoint
        # Register no-op success mapper
        self.context.rpc_manager.call.auth_register_success_mapper(
            None, "auth_noop_success_mapper"
        )
        # Register RPC success mapper
        self.context.rpc_manager.call.auth_register_success_mapper(
            "rpc", "auth_rpc_success_mapper"
        )

    @web.deinit()
    def success_mappers_deinit(self):
        # Unregister RPC success mapper
        self.context.rpc_manager.call.auth_unregister_success_mapper(
            "rpc"
        )
        # Unregister no-op success mapper
        self.context.rpc_manager.call.auth_unregister_success_mapper(
            None
        )
