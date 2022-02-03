#!/usr/bin/python3
# coding=utf-8

#   Copyright 2022 getcarrier.io
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

""" Module """

import re
import uuid
import urllib
import datetime

import jwt  # pylint: disable=E0401
import flask  # pylint: disable=E0401
import sqlalchemy  # pylint: disable=E0401

from pylon.core.tools import log  # pylint: disable=E0611,E0401
from pylon.core.tools import web  # pylint: disable=E0611,E0401
from pylon.core.tools import module  # pylint: disable=E0611,E0401

from pylon.core.tools.context import Context as Holder  # pylint: disable=E0611,E0401

from .db import db_migrations
from .db import db_tools
from .tools import rpc_tools


class Module(module.ModuleModel):
    """ Pylon module """

    def __init__(self, context, descriptor):
        self.context = context
        self.descriptor = descriptor
        # Registry
        self.auth_providers = dict()  # name -> {login_route/url, logout_route/url}
        self.auth_processors = list()  # [rpc_endpoint_name]
        self.credential_handlers = dict()  # type -> rpc_endpoint
        self.success_mappers = dict()  # target -> rpc_endpoint
        self.info_mappers = dict()  # target -> rpc_endpoint
        self.public_rules = list()  # [rule]
        # DB
        self.db = Holder()
        self.db.tbl = Holder()
        self.db.url = self.descriptor.config.get("db_url", None)
        self.db.options = self.descriptor.config.get("db_options", dict())
        # RPCs
        self._rpcs = [
            [self._noop_success_mapper, "auth_noop_success_mapper"],
            [self._rpc_success_mapper, "auth_rpc_success_mapper"],
            [self._handle_bearer_token, "auth_handle_bearer_token"],
            #
            [
                self._get_referenced_auth_context,
                "auth_get_referenced_auth_context"
            ],
            [self._get_session_cookie_name, "auth_get_session_cookie_name"],
            #
            [self._register_auth_provider, "auth_register_auth_provider"],
            [self._unregister_auth_provider, "auth_unregister_auth_provider"],
            #
            [self._register_auth_processor, "auth_register_auth_processor"],
            [self._unregister_auth_processor, "auth_unregister_auth_processor"],
            #
            [
                self._register_credential_handler,
                "auth_register_credential_handler"
            ],
            [
                self._unregister_credential_handler,
                "auth_unregister_credential_handler"
            ],
            #
            [self._register_success_mapper, "auth_register_success_mapper"],
            [self._unregister_success_mapper, "auth_unregister_success_mapper"],
            #
            [self._register_info_mapper, "auth_register_info_mapper"],
            [self._unregister_info_mapper, "auth_unregister_info_mapper"],
            #
            [self._add_public_rule, "auth_add_public_rule"],
            [self._remove_public_rule, "auth_remove_public_rule"],
            #
            [self._add_user, "auth_add_user"],
            [self._delete_user, "auth_delete_user"],
            [self._get_user, "auth_get_user"],
            [self._list_users, "auth_list_users"],
            #
            [self._add_user_provider, "auth_add_user_provider"],
            [self._remove_user_provider, "auth_remove_user_provider"],
            [self._get_user_from_provider, "auth_get_user_from_provider"],
            [self._list_user_providers, "auth_list_user_providers"],
            #
            [self._add_group, "auth_add_group"],
            [self._delete_group, "auth_delete_group"],
            [self._get_group, "auth_get_group"],
            [self._list_groups, "auth_list_groups"],
            [self._walk_group_tree, "auth_walk_group_tree"],
            #
            [self._add_group_provider, "auth_add_group_provider"],
            [self._remove_group_provider, "auth_remove_group_provider"],
            [self._get_group_from_provider, "auth_get_group_from_provider"],
            [self._list_group_providers, "auth_list_group_providers"],
            #
            [self._add_user_group, "auth_add_user_group"],
            [self._remove_user_group, "auth_remove_user_group"],
            [self._get_user_group_ids, "auth_get_user_group_ids"],
            [self._get_user_groups, "auth_get_user_groups"],
            [self._list_user_groups, "auth_list_user_groups"],
            #
            [self._add_scope, "auth_add_scope"],
            [self._delete_scope, "auth_delete_scope"],
            [self._get_scope, "auth_get_scope"],
            [self._list_scopes, "auth_list_scopes"],
            [self._walk_scope_tree, "auth_walk_scope_tree"],
            #
            [self._add_group_permission, "auth_add_group_permission"],
            [self._remove_group_permission, "auth_remove_group_permission"],
            [self._get_group_permissions, "auth_get_group_permissions"],
            [self._list_group_permissions, "auth_list_group_permissions"],
            #
            [self._add_user_permission, "auth_add_user_permission"],
            [self._remove_user_permission, "auth_remove_user_permission"],
            [self._get_user_permissions, "auth_get_user_permissions"],
            [self._list_user_permissions, "auth_list_user_permissions"],
            #
            [self._add_token, "auth_add_token"],
            [self._delete_token, "auth_delete_token"],
            [self._get_token, "auth_get_token"],
            [self._list_tokens, "auth_list_tokens"],
            [self._encode_token, "auth_encode_token"],
            [self._decode_token, "auth_decode_token"],
            #
            [self._add_token_permission, "auth_add_token_permission"],
            [self._remove_token_permission, "auth_remove_token_permission"],
            [self._get_token_permissions, "auth_get_token_permissions"],
            [self._list_token_permissions, "auth_list_token_permissions"],
            [self._resolve_token_permissions, "auth_resolve_token_permissions"],
        ]

    #
    # Module
    #

    def init(self):
        """ Init module """
        log.info("Initializing module")
        # Run DB migrations
        db_migrations.run_db_migrations(self, self.db.url)
        # Connect to DB
        module_name = self.descriptor.name
        #
        self.db.engine = sqlalchemy.create_engine(
            self.db.url, **self.db.options
        )
        self.db.metadata = sqlalchemy.MetaData()
        #
        self.db.tbl.user = sqlalchemy.Table(
            f"{module_name}__user", self.db.metadata,
            autoload_with=self.db.engine,
        )
        self.db.tbl.user_provider = sqlalchemy.Table(
            f"{module_name}__user_provider", self.db.metadata,
            autoload_with=self.db.engine,
        )
        self.db.tbl.group = sqlalchemy.Table(
            f"{module_name}__group", self.db.metadata,
            autoload_with=self.db.engine,
        )
        self.db.tbl.group_provider = sqlalchemy.Table(
            f"{module_name}__group_provider", self.db.metadata,
            autoload_with=self.db.engine,
        )
        self.db.tbl.user_group = sqlalchemy.Table(
            f"{module_name}__user_group", self.db.metadata,
            autoload_with=self.db.engine,
        )
        self.db.tbl.scope = sqlalchemy.Table(
            f"{module_name}__scope", self.db.metadata,
            autoload_with=self.db.engine,
        )
        self.db.tbl.user_permission = sqlalchemy.Table(
            f"{module_name}__user_permission", self.db.metadata,
            autoload_with=self.db.engine,
        )
        self.db.tbl.group_permission = sqlalchemy.Table(
            f"{module_name}__group_permission", self.db.metadata,
            autoload_with=self.db.engine,
        )
        self.db.tbl.token = sqlalchemy.Table(
            f"{module_name}__token", self.db.metadata,
            autoload_with=self.db.engine,
        )
        self.db.tbl.token_permission = sqlalchemy.Table(
            f"{module_name}__token_permission", self.db.metadata,
            autoload_with=self.db.engine,
        )
        # Init Blueprint
        self.descriptor.init_blueprint(
            url_prefix="/",
            static_url_prefix="/",
        )
        # Init RPCs
        for rpc_item in self._rpcs:
            self.context.rpc_manager.register_function(*rpc_item)
        # Register no-op success mapper
        self.context.rpc_manager.call.auth_register_success_mapper(
            None, "auth_noop_success_mapper"
        )
        # Register RPC success mapper
        self.context.rpc_manager.call.auth_register_success_mapper(
            "rpc", "auth_rpc_success_mapper"
        )
        # Register bearer token handler
        self.context.rpc_manager.call.auth_register_credential_handler(
            "bearer", "auth_handle_bearer_token"
        )
        # Register auth tool
        self.descriptor.register_tool("auth", self)

    def deinit(self):  # pylint: disable=R0201
        """ De-init module """
        log.info("De-initializing module")
        # Unregister auth tool
        self.descriptor.unregister_tool("auth")
        # Unregister bearer token handler
        self.context.rpc_manager.call.auth_unregister_credential_handler(
            "bearer"
        )
        # Unregister RPC success mapper
        self.context.rpc_manager.call.auth_unregister_success_mapper(
            "rpc"
        )
        # Unregister no-op success mapper
        self.context.rpc_manager.call.auth_unregister_success_mapper(
            None
        )
        # De-init RPCs
        for rpc_item in self._rpcs:
            self.context.rpc_manager.unregister_function(*rpc_item)
        # De-init DB
        self.db.engine.dispose()

    #
    # Auth, login, logout, info
    #

    @web.route("/auth")
    def auth(self):  # pylint: disable=R0201
        """ Traefik ForwardAuth endpoint """
        # Check if we got request from Traefik
        traefik_headers = [
            "X-Forwarded-Method",
            "X-Forwarded-Proto",
            "X-Forwarded-Host",
            "X-Forwarded-Uri",
            "X-Forwarded-For",
        ]
        for header in traefik_headers:
            if header not in flask.request.headers:
                # Not a traefik request
                return self.access_denied_reply()
        # Get source request data
        source = {
            "method": flask.request.headers.get("X-Forwarded-Method"),
            "proto": flask.request.headers.get("X-Forwarded-Proto"),
            "host": flask.request.headers.get("X-Forwarded-Host"),
            "uri": flask.request.headers.get("X-Forwarded-Uri"),
            "ip": flask.request.headers.get("X-Forwarded-For"),
            #
            "target": flask.request.args.get("target", None),
            "scope": flask.request.args.get("scope", None),
        }
        # Check public rules
        for rule in self.public_rules:
            if self._public_rule_matches(rule, source):
                # Public request
                return self.access_success_reply(source, "public")
        # Check auth header
        if "Authorization" in flask.request.headers:
            auth_header = flask.request.headers.get("Authorization")
            if " " not in auth_header:
                # Invalid auth header
                return self.access_denied_reply()
            #
            credential_type, credential_data = auth_header.split(" ", 1)
            if credential_type not in self.credential_handlers:
                # No credential handler
                return self.access_denied_reply()
            #
            try:
                auth_type, auth_id, auth_reference = \
                self.credential_handlers[credential_type](
                    source, credential_data
                )
            except:
                # Bad credential
                return self.access_denied_reply()
            #
            return self.access_success_reply(
                source, auth_type, auth_id, auth_reference
            )
        # Browser auth
        auth_ctx = self.get_auth_context()
        if auth_ctx["done"] and \
                (
                    auth_ctx["expiration"] is None or
                    datetime.datetime.now() < auth_ctx["expiration"]
                ):
            # Auth done
            return self.access_success_reply(
                source,
                auth_type="user",
                auth_id=str(auth_ctx["user_id"]) \
                    if auth_ctx["user_id"] is not None else "-",
                auth_reference=flask.request.cookies.get(
                    self.context.app.session_cookie_name, "-"
                ),
            )
        # Auth needed or expired
        self.set_auth_context(dict())
        target_token = self.sign_target_url(self.make_source_url(source))
        return self.access_needed_redirect(target_token)

    @web.route("/login")
    def login(self):  # pylint: disable=R0201
        """ Login endpoint """
        self.set_auth_context(dict())
        target_token = flask.request.args.get(
            "target_to",
            self.sign_target_url(
                self.descriptor.config.get("default_login_url", "/")
            )
        )
        return self.access_needed_redirect(target_token)

    @web.route("/logout")
    def logout(self):  # pylint: disable=R0201
        """ Logout endpoint """
        target_token = flask.request.args.get(
            "target_to",
            self.sign_target_url(
                self.descriptor.config.get("default_logout_url", "/")
            )
        )
        return self.logout_needed_redirect(target_token)

    @web.route("/info")
    def info(self):  # pylint: disable=R0201
        """ Info endpoint """
        target = flask.request.args.get("target", None)
        scope = flask.request.args.get("scope", None)
        #
        if target not in self.info_mappers:
            return self.access_denied_reply()
        #
        auth_ctx = self.get_auth_context()
        #
        try:
            mimetype, data = self.info_mappers[target](auth_ctx, scope)
        except:
            return self.access_denied_reply()
        #
        response = flask.make_response(data)
        response.mimetype = mimetype
        return response

    #
    # Tools
    #

    @staticmethod
    def make_source_url(source):
        """ Make original URL from source """
        proto = source.get("proto")
        host = source.get("host")
        uri = source.get("uri")
        return f"{proto}://{host}{uri}"

    def sign_target_url(self, url):
        """ Sign and encode URL in JWT token """
        return jwt.encode(
            {"url": url},
            self.context.app.secret_key,
            algorithm="HS256",
        )

    def verify_target_url(self, url_token):
        """ Verify and decode URL from JWT token """
        try:
            url_data = jwt.decode(
                url_token, self.context.app.secret_key, algorithms=["HS256"]
            )
        except:
            raise ValueError("Invalid URL token")
        #
        return url_data["url"]

    def get_auth_context(self, session=None):
        """ Get current auth context from session """
        if session is None:
            session = flask.session
        #
        return {
            "done": session.get("auth_done", False),
            "error": session.get("auth_error", ""),
            "expiration": session.get("auth_expiration", None),
            "provider": session.get("auth_provider", None),
            "provider_attr": session.get("auth_provider_attr", dict()),
            "user_id": session.get("auth_user_id", None),
        }

    def set_auth_context(self, auth_context):
        """ Save current auth context in session """
        flask.session["auth_done"] = auth_context.get("done", False)
        flask.session["auth_error"] = auth_context.get("error", "")
        flask.session["auth_expiration"] = auth_context.get("expiration", None)
        flask.session["auth_provider"] = auth_context.get("provider", None)
        flask.session["auth_provider_attr"] = auth_context.get(
            "provider_attr", dict()
        )
        flask.session["auth_user_id"] = auth_context.get("user_id", None)

    def access_denied_reply(self):
        """ Traefik/client: bad auth reply/redirect """
        if "auth_denied_url" in self.descriptor.config:
            return flask.redirect(self.descriptor.config.get("auth_denied_url"))
        return flask.make_response("Access Denied", 403)

    def access_success_reply(
            self, source,
            auth_type, auth_id="-", auth_reference="-",
        ):
        """ Traefik: auth OK reply """
        auth_target = source["target"]
        if auth_target not in self.success_mappers:
            return self.access_denied_reply()
        #
        try:
            auth_allow, auth_headers = self.success_mappers[auth_target](
                source, auth_type, auth_id, auth_reference
            )
        except:
            auth_allow = False
        #
        if not auth_allow:
            return self.access_denied_reply()
        #
        response = flask.make_response("OK")
        for key, value in auth_headers.items():
            response.headers[key] = str(value)
        return response

    def access_needed_redirect(self, target_token):
        """ Client: auth redirect """
        target_provider = self.descriptor.config.get("auth_provider", None)
        if target_provider not in self.auth_providers:
            return self.access_denied_reply()
        target_info = self.auth_providers[target_provider]
        #
        if target_info["login_route"] is not None:
            try:
                return flask.redirect(
                    flask.url_for(
                        target_info["login_route"],
                        target_to=target_token,
                    )
                )
            except:
                return self.access_denied_reply()
        #
        if target_info["login_url"] is not None:
            try:
                url_params = urllib.parse.urlencode({"target_to": target_token})
                return flask.redirect(
                    f'{target_info["login_url"]}?{url_params}'
                )
            except:
                return self.access_denied_reply()
        #
        return self.access_denied_reply()

    def access_success_redirect(self, target_token):
        """ Client: auth OK redirect """
        auth_ctx = self.get_auth_context()
        #
        for processor_endpoint in self.auth_processors:
            processor_rpc = getattr(
                self.context.rpc_manager.call, processor_endpoint
            )
            #
            try:
                auth_ctx = processor_rpc(auth_ctx)
            except:
                return self.access_denied_reply()
        #
        self.set_auth_context(auth_ctx)
        #
        try:
            target_url = self.verify_target_url(target_token)
        except:
            target_url = self.descriptor.config.get("default_login_url", "/")
        #
        return flask.redirect(target_url)

    def logout_needed_redirect(self, target_token):
        """ Client: logout redirect """
        target_provider = self.descriptor.config.get("auth_provider", None)
        if target_provider not in self.auth_providers:
            return self.access_denied_reply()
        target_info = self.auth_providers[target_provider]
        #
        if target_info["logout_route"] is not None:
            try:
                return flask.redirect(
                    flask.url_for(
                        target_info["logout_route"],
                        target_to=target_token,
                    )
                )
            except:
                return self.access_denied_reply()
        #
        if target_info["logout_url"] is not None:
            try:
                url_params = urllib.parse.urlencode({"target_to": target_token})
                return flask.redirect(
                    f'{target_info["logout_url"]}?{url_params}'
                )
            except:
                return self.access_denied_reply()
        #
        return self.access_denied_reply()

    def logout_success_redirect(self, target_token):
        """ Client: logout OK redirect """
        self.set_auth_context(dict())
        try:
            target_url = self.verify_target_url(target_token)
        except:
            target_url = self.descriptor.config.get("default_logout_url", "/")
        #
        return flask.redirect(target_url)

    @staticmethod
    def _public_rule_matches(rule, source):
        for key, obj in rule.items():
            if not obj.fullmatch(source[key]):
                return False
        #
        return True

    #
    # RPC: No-op success mapper
    #

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _noop_success_mapper(self, source, auth_type, auth_id, auth_reference):
        return True, dict()

    #
    # RPC: RPC success mapper
    #

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _rpc_success_mapper(self, source, auth_type, auth_id, auth_reference):
        headers = dict()
        #
        headers["X-Auth-Type"] = str(auth_type)
        headers["X-Auth-ID"] = str(auth_id)
        headers["X-Auth-Reference"] = str(auth_reference)
        #
        return True, headers

    #
    # RPC: Bearer token handler
    #

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _handle_bearer_token(self, source, token_data):
        try:
            token = self._decode_token(token_data)
        except:
            raise ValueError("Bad token")
        #
        if token["expires"] is not None and \
                datetime.datetime.now() >= token["expires"]:
            raise ValueError("Token expired")
        #
        return "token", token["id"], "-"

    #
    # RPC: referenced auth context
    #

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _get_referenced_auth_context(self, auth_reference):
        request = Holder()
        request.cookies = {
            self.context.app.session_cookie_name: auth_reference
        }
        #
        with self.context.app.app_context():
            session = self.context.app.session_interface.open_session(
                self.context.app, request,
            )
        #
        return self.get_auth_context(session)

    #
    # RPC: session cookie name
    #

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _get_session_cookie_name(self):
        return self.context.app.session_cookie_name

    #
    # RPC: auth providers
    #

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _register_auth_provider(
            self, name,
            login_route=None, login_url=None,
            logout_route=None, logout_url=None
    ):
        if name in self.auth_providers:
            raise ValueError(
                "Provider is already registered: %s", name
            )
        #
        self.auth_providers[name] = {
            "login_route": login_route,
            "login_url": login_url,
            "logout_route": logout_route,
            "logout_url": logout_url,
        }

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _unregister_auth_provider(self, name):
        if name not in self.auth_providers:
            raise ValueError(
                "Provider is not registered: %s", name
            )
        #
        self.auth_providers.pop(name)

    #
    # RPC: auth processors
    #

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _register_auth_processor(self, rpc_endpoint_name):
        if rpc_endpoint_name in self.auth_processors:
            raise ValueError(
                "Processor is already registered: %s", rpc_endpoint_name
            )
        #
        self.auth_processors.append(rpc_endpoint_name)

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _unregister_auth_processor(self, rpc_endpoint_name):
        if rpc_endpoint_name not in self.auth_processors:
            raise ValueError(
                "Processor is not registered: %s", rpc_endpoint_name
            )
        #
        self.auth_processors.remove(rpc_endpoint_name)

    #
    # RPC: credential handlers
    #

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _register_credential_handler(self, credential_type, rpc_endpoint):
        if credential_type in self.credential_handlers:
            raise ValueError(
                "Credential type is already registered: %s", credential_type
            )
        #
        self.credential_handlers[credential_type] = getattr(
            self.context.rpc_manager.call, rpc_endpoint
        )

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _unregister_credential_handler(self, credential_type):
        if credential_type not in self.credential_handlers:
            raise ValueError(
                "Credential type is not registered: %s", credential_type
            )
        #
        self.credential_handlers.pop(credential_type)

    #
    # RPC: success mappers
    #

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _register_success_mapper(self, target, rpc_endpoint):
        if target in self.success_mappers:
            raise ValueError(
                "Target is already registered: %s", target
            )
        #
        self.success_mappers[target] = getattr(
            self.context.rpc_manager.call, rpc_endpoint
        )

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _unregister_success_mapper(self, target):
        if target not in self.success_mappers:
            raise ValueError(
                "Target is not registered: %s", target
            )
        #
        self.success_mappers.pop(target)

    #
    # RPC: info mappers
    #

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _register_info_mapper(self, target, rpc_endpoint):
        if target in self.info_mappers:
            raise ValueError(
                "Target is already registered: %s", target
            )
        #
        self.info_mappers[target] = getattr(
            self.context.rpc_manager.call, rpc_endpoint
        )

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _unregister_info_mapper(self, target):
        if target not in self.info_mappers:
            raise ValueError(
                "Target is not registered: %s", target
            )
        #
        self.info_mappers.pop(target)

    #
    # RPC: public rules
    #

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _add_public_rule(self, rule):
        rule_obj = dict()
        for key, regex in rule.items():
            rule_obj[key] = re.compile(regex)
        #
        if rule_obj not in self.public_rules:
            self.public_rules.append(rule_obj)

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _remove_public_rule(self, rule):
        rule_obj = dict()
        for key, regex in rule.items():
            rule_obj[key] = re.compile(regex)
        #
        while rule_obj in self.public_rules:
            self.public_rules.remove(rule_obj)

    #
    # RPC: users
    #

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _add_user(self, email="", name="", id=...):
        values = {
            "email": email,
            "name": name,
        }
        #
        if id is not ...:
            values["id"] = id
        #
        with self.db.engine.connect() as connection:
            return connection.execute(
                self.db.tbl.user.insert().values(**values)
            ).inserted_primary_key[0]

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _delete_user(self, id):
        with self.db.engine.connect() as connection:
            return connection.execute(
                self.db.tbl.user.delete().where(
                    self.db.tbl.user.c.id == id
                )
            ).rowcount

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _get_user(self, id=None, email=None, name=None):
        if id is not None:
            with self.db.engine.connect() as connection:
                user = connection.execute(
                    self.db.tbl.user.select().where(
                        self.db.tbl.user.c.id == id,
                    )
                ).mappings().one()
            return db_tools.sqlalchemy_mapping_to_dict(user)
        #
        if email is not None:
            with self.db.engine.connect() as connection:
                user = connection.execute(
                    self.db.tbl.user.select().where(
                        self.db.tbl.user.c.email == email,
                    )
                ).mappings().one()
            return db_tools.sqlalchemy_mapping_to_dict(user)
        #
        if name is not None:
            with self.db.engine.connect() as connection:
                user = connection.execute(
                    self.db.tbl.user.select().where(
                        self.db.tbl.user.c.name == name,
                    )
                ).mappings().one()
            return db_tools.sqlalchemy_mapping_to_dict(user)
        #
        raise ValueError("ID or name is not provided")

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _list_users(self):
        with self.db.engine.connect() as connection:
            users = connection.execute(
                self.db.tbl.user.select()
            ).mappings().all()
        #
        return [db_tools.sqlalchemy_mapping_to_dict(item) for item in users]

    #
    # RPC: user provider
    #

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _add_user_provider(self, user_id, provider_ref):
        with self.db.engine.connect() as connection:
            return connection.execute(
                self.db.tbl.user_provider.insert().values(
                    user_id=user_id,
                    provider_ref=provider_ref,
                )
            ).inserted_primary_key[0]

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _remove_user_provider(self, user_id, provider_ref):
        with self.db.engine.connect() as connection:
            return connection.execute(
                self.db.tbl.user_provider.delete().where(
                    self.db.tbl.user_provider.c.user_id == user_id,
                    self.db.tbl.user_provider.c.provider_ref == provider_ref,
                )
            ).rowcount

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _get_user_from_provider(self, provider_ref):
        with self.db.engine.connect() as connection:
            user_provider = connection.execute(
                self.db.tbl.user_provider.select().where(
                    self.db.tbl.user_provider.c.provider_ref == provider_ref,
                )
            ).mappings().one()
        #
        return self._get_user(id=user_provider["user_id"])

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _list_user_providers(self, user_id=None):
        with self.db.engine.connect() as connection:
            if user_id is not None:
                providers = connection.execute(
                    self.db.tbl.user_provider.select().where(
                        self.db.tbl.user_provider.c.user_id == user_id,
                    )
                ).mappings().all()
            else:
                providers = connection.execute(
                    self.db.tbl.user_provider.select()
                ).mappings().all()
        #
        return [
            db_tools.sqlalchemy_mapping_to_dict(item) for item in providers
        ]

    #
    # RPC: groups
    #

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _add_group(self, name="", parent_id=None, id=...):
        values = {
            "name": name,
            "parent_id": parent_id,
        }
        #
        if id is not ...:
            values["id"] = id
        #
        with self.db.engine.connect() as connection:
            return connection.execute(
                self.db.tbl.group.insert().values(**values)
            ).inserted_primary_key[0]

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _delete_group(self, id):
        with self.db.engine.connect() as connection:
            return connection.execute(
                self.db.tbl.group.delete().where(
                    self.db.tbl.group.c.id == id
                )
            ).rowcount

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _get_group(self, id):
        with self.db.engine.connect() as connection:
            group = connection.execute(
                self.db.tbl.group.select().where(
                    self.db.tbl.group.c.id == id,
                )
            ).mappings().one()
        return db_tools.sqlalchemy_mapping_to_dict(group)

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _list_groups(self):
        with self.db.engine.connect() as connection:
            groups = connection.execute(
                self.db.tbl.group.select()
            ).mappings().all()
        #
        return [db_tools.sqlalchemy_mapping_to_dict(item) for item in groups]

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _walk_group_tree(self, id):
        groups = self._list_groups()
        group_map = {item["id"]:item for item in groups}
        #
        result = list()
        #
        current_id = id
        while True:
            if current_id not in group_map:
                break
            #
            item = group_map[current_id]
            result.append(item)
            #
            if item["parent_id"] is None:
                break
            #
            current_id = item["parent_id"]
        #
        return result

    #
    # RPC: group provider
    #

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _add_group_provider(self, group_id, provider_ref):
        with self.db.engine.connect() as connection:
            return connection.execute(
                self.db.tbl.group_provider.insert().values(
                    group_id=group_id,
                    provider_ref=provider_ref,
                )
            ).inserted_primary_key[0]

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _remove_group_provider(self, group_id, provider_ref):
        with self.db.engine.connect() as connection:
            return connection.execute(
                self.db.tbl.group_provider.delete().where(
                    self.db.tbl.group_provider.c.group_id == group_id,
                    self.db.tbl.group_provider.c.provider_ref == provider_ref,
                )
            ).rowcount

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _get_group_from_provider(self, provider_ref):
        with self.db.engine.connect() as connection:
            group_provider = connection.execute(
                self.db.tbl.group_provider.select().where(
                    self.db.tbl.group_provider.c.provider_ref == provider_ref,
                )
            ).mappings().one()
        #
        return self._get_group(id=group_provider["group_id"])

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _list_group_providers(self, group_id=None):
        with self.db.engine.connect() as connection:
            if group_id is not None:
                providers = connection.execute(
                    self.db.tbl.group_provider.select().where(
                        self.db.tbl.group_provider.c.group_id == group_id,
                    )
                ).mappings().all()
            else:
                providers = connection.execute(
                    self.db.tbl.group_provider.select()
                ).mappings().all()
        #
        return [
            db_tools.sqlalchemy_mapping_to_dict(item) for item in providers
        ]

    #
    # RPC: user groups
    #

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _add_user_group(self, user_id, group_id):
        with self.db.engine.connect() as connection:
            return connection.execute(
                self.db.tbl.user_group.insert().values(
                    user_id=user_id,
                    group_id=group_id,
                )
            ).inserted_primary_key[0]

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _remove_user_group(self, user_id, group_id):
        with self.db.engine.connect() as connection:
            return connection.execute(
                self.db.tbl.user_group.delete().where(
                    self.db.tbl.user_group.c.user_id == user_id,
                    self.db.tbl.user_group.c.group_id == group_id,
                )
            ).rowcount

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _get_user_group_ids(self, user_id):
        with self.db.engine.connect() as connection:
            user_groups = connection.execute(
                self.db.tbl.user_group.select().where(
                    self.db.tbl.user_group.c.user_id == user_id,
                )
            ).mappings().all()
        #
        return [
            item["group_id"] for item in user_groups
        ]

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _get_user_groups(self, user_id):
        return [
            self._get_group(group_id)
            for group_id in self._get_user_group_ids(user_id)
        ]

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _list_user_groups(self, user_id=None):
        with self.db.engine.connect() as connection:
            if user_id is not None:
                user_groups = connection.execute(
                    self.db.tbl.user_group.select().where(
                        self.db.tbl.user_group.c.user_id == user_id,
                    )
                ).mappings().all()
            else:
                user_groups = connection.execute(
                    self.db.tbl.user_group.select()
                ).mappings().all()
        #
        return [
            db_tools.sqlalchemy_mapping_to_dict(item) for item in user_groups
        ]

    #
    # RPC: scopes
    #

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _add_scope(self, name="", parent_id=None, id=...):
        values = {
            "name": name,
            "parent_id": parent_id,
        }
        #
        if id is not ...:
            values["id"] = id
        #
        with self.db.engine.connect() as connection:
            return connection.execute(
                self.db.tbl.scope.insert().values(**values)
            ).inserted_primary_key[0]

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _delete_scope(self, id):
        with self.db.engine.connect() as connection:
            return connection.execute(
                self.db.tbl.scope.delete().where(
                    self.db.tbl.scope.c.id == id
                )
            ).rowcount

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _get_scope(self, id):
        with self.db.engine.connect() as connection:
            scope = connection.execute(
                self.db.tbl.scope.select().where(
                    self.db.tbl.scope.c.id == id,
                )
            ).mappings().one()
        return db_tools.sqlalchemy_mapping_to_dict(scope)

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _list_scopes(self):
        with self.db.engine.connect() as connection:
            scopes = connection.execute(
                self.db.tbl.scope.select()
            ).mappings().all()
        #
        return [db_tools.sqlalchemy_mapping_to_dict(item) for item in scopes]

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _walk_scope_tree(self, id):
        scopes = self._list_scopes()
        scope_map = {item["id"]:item for item in scopes}
        #
        result = list()
        #
        current_id = id
        while True:
            if current_id not in scope_map:
                break
            #
            item = scope_map[current_id]
            result.append(item)
            #
            if item["parent_id"] is None:
                break
            #
            current_id = item["parent_id"]
        #
        return result

    #
    # RPC: group permission
    #

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _add_group_permission(self, group_id, scope_id, permission):
        with self.db.engine.connect() as connection:
            return connection.execute(
                self.db.tbl.group_permission.insert().values(
                    group_id=group_id,
                    scope_id=scope_id,
                    permission=permission,
                )
            ).inserted_primary_key[0]

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _remove_group_permission(self, group_id, scope_id, permission):
        with self.db.engine.connect() as connection:
            return connection.execute(
                self.db.tbl.group_permission.delete().where(
                    self.db.tbl.group_permission.c.group_id == group_id,
                    self.db.tbl.group_permission.c.scope_id == scope_id,
                    self.db.tbl.group_permission.c.permission == permission,
                )
            ).rowcount

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _get_group_permissions(self, group_id, scope_id):
        group_scopes = [
            scope["id"] for scope in self._walk_scope_tree(scope_id)
        ]
        #
        with self.db.engine.connect() as connection:
            data = connection.execute(
                self.db.tbl.group_permission.select().where(
                    self.db.tbl.group_permission.c.group_id == group_id,
                    self.db.tbl.group_permission.c.scope_id.in_(group_scopes),
                )
            ).mappings().all()
        #
        result = list(set([item["permission"] for item in data]))
        result.sort()
        #
        return result

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _list_group_permissions(self, group_id=None):
        with self.db.engine.connect() as connection:
            if group_id is not None:
                permissions = connection.execute(
                    self.db.tbl.group_permission.select().where(
                        self.db.tbl.group_permission.c.group_id == group_id,
                    )
                ).mappings().all()
            else:
                permissions = connection.execute(
                    self.db.tbl.group_permission.select()
                ).mappings().all()
        #
        return [
            db_tools.sqlalchemy_mapping_to_dict(item) for item in permissions
        ]

    #
    # RPC: user permission
    #

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _add_user_permission(self, user_id, scope_id, permission):
        with self.db.engine.connect() as connection:
            return connection.execute(
                self.db.tbl.user_permission.insert().values(
                    user_id=user_id,
                    scope_id=scope_id,
                    permission=permission,
                )
            ).inserted_primary_key[0]

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _remove_user_permission(self, user_id, scope_id, permission):
        with self.db.engine.connect() as connection:
            return connection.execute(
                self.db.tbl.user_permission.delete().where(
                    self.db.tbl.user_permission.c.user_id == user_id,
                    self.db.tbl.user_permission.c.scope_id == scope_id,
                    self.db.tbl.user_permission.c.permission == permission,
                )
            ).rowcount

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _get_user_permissions(self, user_id, scope_id):
        user_scopes = [scope["id"] for scope in self._walk_scope_tree(scope_id)]
        #
        with self.db.engine.connect() as connection:
            data = connection.execute(
                self.db.tbl.user_permission.select().where(
                    self.db.tbl.user_permission.c.user_id == user_id,
                    self.db.tbl.user_permission.c.scope_id.in_(user_scopes),
                )
            ).mappings().all()
        #
        result = set([item["permission"] for item in data])
        #
        user_group_ids = self._get_user_group_ids(user_id)
        for group_id in user_group_ids:
            group_permissions = set(
                self._get_group_permissions(group_id, scope_id)
            )
            result |= group_permissions
        #
        result = list(result)
        result.sort()
        #
        return result

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _list_user_permissions(self, user_id=None):
        with self.db.engine.connect() as connection:
            if user_id is not None:
                permissions = connection.execute(
                    self.db.tbl.user_permission.select().where(
                        self.db.tbl.user_permission.c.user_id == user_id,
                    )
                ).mappings().all()
            else:
                permissions = connection.execute(
                    self.db.tbl.user_permission.select()
                ).mappings().all()
        #
        return [
            db_tools.sqlalchemy_mapping_to_dict(item) for item in permissions
        ]

    #
    # RPC: tokens
    #

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _add_token(self, user_id, name="", expires=None, id=...):
        token_uuid = str(uuid.uuid4())
        #
        values = {
            "uuid": token_uuid,
            "user_id": user_id,
            "expires": expires,
            "name": name,
        }
        #
        if id is not ...:
            values["id"] = id
        #
        #
        with self.db.engine.connect() as connection:
            return connection.execute(
                self.db.tbl.token.insert().values(**values)
            ).inserted_primary_key[0]

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _delete_token(self, id):
        with self.db.engine.connect() as connection:
            return connection.execute(
                self.db.tbl.token.delete().where(
                    self.db.tbl.token.c.id == id
                )
            ).rowcount

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _get_token(self, id=None, uuid=None):
        if id is not None:
            with self.db.engine.connect() as connection:
                token = connection.execute(
                    self.db.tbl.token.select().where(
                        self.db.tbl.token.c.id == id,
                    )
                ).mappings().one()
            return db_tools.sqlalchemy_mapping_to_dict(token)
        #
        if uuid is not None:
            with self.db.engine.connect() as connection:
                token = connection.execute(
                    self.db.tbl.token.select().where(
                        self.db.tbl.token.c.uuid == uuid,
                    )
                ).mappings().one()
            return db_tools.sqlalchemy_mapping_to_dict(token)
        #
        raise ValueError("ID or UUID or name is not provided")

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _list_tokens(self, user_id=None):
        with self.db.engine.connect() as connection:
            if user_id is not None:
                tokens = connection.execute(
                    self.db.tbl.token.select().where(
                        self.db.tbl.token.c.user_id == user_id,
                    )
                ).mappings().all()
            else:
                tokens = connection.execute(
                    self.db.tbl.token.select()
                ).mappings().all()
        #
        return [
            db_tools.sqlalchemy_mapping_to_dict(item) for item in tokens
        ]

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _encode_token(self, id=None, uuid=None):
        if id is not None:
            token = self._get_token(id)
            token_uuid = token["uuid"]
        elif uuid is not None:
            token_uuid = uuid
        else:
            raise ValueError("ID or UUID is not provided")
        #
        return jwt.encode(
            {"uuid": token_uuid},
            self.context.app.secret_key,
            algorithm="HS512",
        )

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _decode_token(self, token):
        try:
            token_data = jwt.decode(
                token, self.context.app.secret_key, algorithms=["HS512"]
            )
        except:
            raise ValueError("Invalid token")
        #
        return self._get_token(uuid=token_data["uuid"])

    #
    # RPC: token permissions
    #

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _add_token_permission(self, token_id, scope_id, permission):
        with self.db.engine.connect() as connection:
            return connection.execute(
                self.db.tbl.token_permission.insert().values(
                    token_id=token_id,
                    scope_id=scope_id,
                    permission=permission,
                )
            ).inserted_primary_key[0]

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _remove_token_permission(self, token_id, scope_id, permission):
        with self.db.engine.connect() as connection:
            return connection.execute(
                self.db.tbl.token_permission.delete().where(
                    self.db.tbl.token_permission.c.token_id == token_id,
                    self.db.tbl.token_permission.c.scope_id == scope_id,
                    self.db.tbl.token_permission.c.permission == permission,
                )
            ).rowcount

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _get_token_permissions(self, token_id, scope_id):
        token = self._get_token(token_id)
        token_scopes = [
            scope["id"] for scope in self._walk_scope_tree(scope_id)
        ]
        #
        with self.db.engine.connect() as connection:
            data = connection.execute(
                self.db.tbl.token_permission.select().where(
                    self.db.tbl.token_permission.c.token_id == token_id,
                    self.db.tbl.token_permission.c.scope_id.in_(token_scopes),
                )
            ).mappings().all()
        #
        user_permissions = set(self._get_user_permissions(
            token["user_id"], scope_id
        ))
        #
        result = set([item["permission"] for item in data]) & user_permissions
        result = list(result)
        result.sort()
        #
        return result

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _list_token_permissions(self, token_id=None):
        with self.db.engine.connect() as connection:
            if token_id is not None:
                permissions = connection.execute(
                    self.db.tbl.token_permission.select().where(
                        self.db.tbl.token_permission.c.token_id == token_id,
                    )
                ).mappings().all()
            else:
                permissions = connection.execute(
                    self.db.tbl.token_permission.select()
                ).mappings().all()
        #
        return [
            db_tools.sqlalchemy_mapping_to_dict(item) for item in permissions
        ]

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _resolve_token_permissions(self, token, scope_id):
        token = self._decode_token(token)
        return self._get_token_permissions(token["id"], scope_id)
