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

import re

from pylon.core.tools import web, log  # pylint: disable=E0401,E0611,W0611

from ..tools import rpc_tools


class RPC:  # pylint: disable=R0903,E1101

    @web.rpc("auth_add_public_rule", "add_public_rule")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def add_public_rule(self, rule):
        rule_obj = {}
        for key, regex in rule.items():
            rule_obj[key] = re.compile(regex)
        #
        if rule_obj not in self.public_rules:
            self.public_rules.append(rule_obj)

    @web.rpc("auth_remove_public_rule", "remove_public_rule")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def remove_public_rule(self, rule):
        rule_obj = {}
        for key, regex in rule.items():
            rule_obj[key] = re.compile(regex)
        #
        while rule_obj in self.public_rules:
            self.public_rules.remove(rule_obj)
