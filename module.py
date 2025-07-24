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

import sqlalchemy  # pylint: disable=E0401
from sqlalchemy.orm import sessionmaker  # pylint: disable=E0401

from pylon.core.tools import log  # pylint: disable=E0611,E0401
from pylon.core.tools import module  # pylint: disable=E0611,E0401

from pylon.core.tools.context import Context as Holder  # pylint: disable=E0611,E0401

from .db import db_migrations


class Module(module.ModuleModel):
    """ Pylon module """

    def __init__(self, context, descriptor):
        self.context = context
        self.descriptor = descriptor
        # DB
        self.db = Holder()
        self.db.tbl = Holder()
        self.db.url = self.descriptor.config.get("db_url", None)
        self.db.options = self.descriptor.config.get("db_options", {})

    #
    # Module
    #

    def init(self):
        """ Init module """
        log.info("Initializing module")
        # Prepare DB
        db_migrations.run_db_migrations(self, self.db.url)
        #
        module_name = self.descriptor.name
        #
        self.db.engine = sqlalchemy.create_engine(
            self.db.url, **self.db.options
        )
        self.db.session = sessionmaker(bind=self.db.engine)()
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
        self.db.tbl.role = sqlalchemy.Table(
            f"{module_name}__role", self.db.metadata,
            autoload_with=self.db.engine,
        )
        self.db.tbl.role_permission = sqlalchemy.Table(
            f"{module_name}__role_permission", self.db.metadata,
            autoload_with=self.db.engine,
        )
        self.db.tbl.user_role = sqlalchemy.Table(
            f"{module_name}__user_role", self.db.metadata,
            autoload_with=self.db.engine,
        )
        # Init
        self.descriptor.init_rpcs()
        self.descriptor.init_methods()
        self.descriptor.init_inits()
        self.descriptor.init_blueprint(
            url_prefix=self.descriptor.config.get("url_prefix", "/"),
            static_url_prefix=self.descriptor.config.get("static_url_prefix", "/"),
        )
        # Register tool
        self.descriptor.register_tool("auth_core", self)

    def deinit(self):
        """ De-init module """
        log.info("De-initializing module")
        # Unregister tool
        self.descriptor.unregister_tool("auth_core")
        # De-init
        self.deinit_blueprint()
        self.deinit_deinits()
        self.deinit_rpcs()
        # Dispose DB
        self.db.engine.dispose()
