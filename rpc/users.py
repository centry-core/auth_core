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

import datetime
from typing import Optional

from sqlalchemy.exc import NoResultFound
from pylon.core.tools import web, log  # pylint: disable=E0401,E0611,W0611

from ..tools import rpc_tools
from ..db import db_tools


class RPC:  # pylint: disable=R0903,E1101

    @web.rpc("auth_add_user", "add_user")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def add_user(self, email: str, name: Optional[str] = '', id_: Optional[int] = None):
        values = {
            "email": email,
        }
        if name:
            values['name'] = name
        if id_:
            values["id"] = id_

        with self.db.engine.connect() as connection:
            return connection.execute(
                self.db.tbl.user.insert().values(**values)
            ).inserted_primary_key[0]

    @web.rpc("auth_update_user", "update_user")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def update_user(
            self,
            id_: int,
            name: Optional[str] = '',
            last_login: Optional[datetime.datetime] = None
    ):
        values = {}
        if name:
            values['name'] = name
        if last_login:
            values["last_login"] = last_login
        with self.db.engine.connect() as connection:
            return connection.execute(
                self.db.tbl.user.update().where(
                    self.db.tbl.user.c.id == id_
                ).values(**values
                         ).returning(
                    self.db.tbl.user.c.id,
                    self.db.tbl.user.c.name
                )
            ).first()

    @web.rpc("auth_delete_user", "delete_user")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def delete_user(self, user_id: int):
        with self.db.engine.connect() as connection:
            return connection.execute(
                self.db.tbl.user.delete().where(
                    self.db.tbl.user.c.id == user_id
                )
            ).rowcount

    @web.rpc("auth_get_user", "get_user")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def get_user(self, user_id: Optional[int] = None,
                  email: Optional[str] = None,
                  name: Optional[str] = None):
        try:
            if user_id is not None:
                with self.db.engine.connect() as connection:
                    user = connection.execute(
                        self.db.tbl.user.select().where(
                            self.db.tbl.user.c.id == user_id,
                        )
                    ).mappings().one()
                return db_tools.sqlalchemy_mapping_to_dict(user)
            if email is not None:
                with self.db.engine.connect() as connection:
                    user = connection.execute(
                        self.db.tbl.user.select().where(
                            self.db.tbl.user.c.email == email,
                        )
                    ).mappings().one()
                return db_tools.sqlalchemy_mapping_to_dict(user)
            if name is not None:
                with self.db.engine.connect() as connection:
                    user = connection.execute(
                        self.db.tbl.user.select().where(
                            self.db.tbl.user.c.name == name,
                        )
                    ).mappings().one()
                return db_tools.sqlalchemy_mapping_to_dict(user)
        except NoResultFound:
            if user_id is not None:
                raise RuntimeError(f"No such user found: id={user_id}") from None
            if email is not None:
                raise RuntimeError(f"No such user found: email={email}") from None
            if name is not None:
                raise RuntimeError(f"No such user found: name={name}") from None
            raise RuntimeError("No such user found") from None
        #
        raise ValueError("ID or name is not provided")

    @web.rpc("auth_list_users", "list_users")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def list_users(self, user_ids: Optional[list] = None) -> list[dict]:
        query = self.db.tbl.user.select()
        if user_ids:
            query = query.where(
                self.db.tbl.user.c.id.in_(user_ids),
            )
        with self.db.engine.connect() as connection:
            users = connection.execute(query).mappings().all()
        return [db_tools.sqlalchemy_mapping_to_dict(item) for item in users]
