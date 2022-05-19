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

""" DB migration """

revision = "202202021633"
down_revision = None
branch_labels = None

from alembic import op
import sqlalchemy as sa

def upgrade(module, payload):
    module_name = module.descriptor.name
    #
    op.create_table(
        f"{module_name}__user",
        sa.Column("id", sa.Integer, primary_key=True, index=True),
        sa.Column("email", sa.Text, index=True, unique=True),
        sa.Column("name", sa.Text, index=True),
    )
    #
    op.create_table(
        f"{module_name}__user_provider",
        sa.Column(
            "user_id", sa.Integer,
            sa.ForeignKey(
                f"{module_name}__user.id",
                onupdate="CASCADE", ondelete="CASCADE"
            ),
            primary_key=True, index=True,
        ),
        sa.Column(
            "provider_ref", sa.Text,
            primary_key=True, index=True, unique=True,
        ),
    )
    #
    op.create_table(
        f"{module_name}__group",
        sa.Column("id", sa.Integer, primary_key=True, index=True),
        sa.Column(
            "parent_id", sa.Integer,
            sa.ForeignKey(
                f"{module_name}__group.id",
                onupdate="CASCADE", ondelete="SET NULL"
            ),
        ),
        sa.Column("name", sa.Text, index=True),
    )
    #
    op.create_table(
        f"{module_name}__group_provider",
        sa.Column(
            "group_id", sa.Integer,
            sa.ForeignKey(
                f"{module_name}__group.id",
                onupdate="CASCADE", ondelete="CASCADE"
            ),
            primary_key=True, index=True,
        ),
        sa.Column(
            "provider_ref", sa.Text,
            primary_key=True, index=True, unique=True,
        ),
    )
    #
    op.create_table(
        f"{module_name}__user_group",
        sa.Column(
            "user_id", sa.Integer,
            sa.ForeignKey(
                f"{module_name}__user.id",
                onupdate="CASCADE", ondelete="CASCADE"
            ),
            primary_key=True, index=True,
        ),
        sa.Column(
            "group_id", sa.Integer,
            sa.ForeignKey(
                f"{module_name}__group.id",
                onupdate="CASCADE", ondelete="CASCADE"
            ),
            primary_key=True, index=True,
        ),
    )
    #
    scope_table = op.create_table(
        f"{module_name}__scope",
        sa.Column("id", sa.Integer, primary_key=True, index=True),
        sa.Column(
            "parent_id", sa.Integer,
            sa.ForeignKey(
                f"{module_name}__scope.id",
                onupdate="CASCADE", ondelete="SET NULL"
            ),
        ),
        sa.Column("name", sa.Text, index=True),
    )
    #
    op.bulk_insert(
        scope_table,
        [
            {"name": "Global", "parent_id": None},
        ]
    )
    #
    op.create_table(
        f"{module_name}__user_permission",
        sa.Column(
            "user_id", sa.Integer,
            sa.ForeignKey(
                f"{module_name}__user.id",
                onupdate="CASCADE", ondelete="CASCADE"
            ),
            primary_key=True, index=True,
        ),
        sa.Column(
            "scope_id", sa.Integer,
            sa.ForeignKey(
                f"{module_name}__scope.id",
                onupdate="CASCADE", ondelete="CASCADE"
            ),
            primary_key=True, index=True,
        ),
        sa.Column("permission", sa.Text, primary_key=True),
    )
    #
    op.create_table(
        f"{module_name}__group_permission",
        sa.Column(
            "group_id", sa.Integer,
            sa.ForeignKey(
                f"{module_name}__group.id",
                onupdate="CASCADE", ondelete="CASCADE"
            ),
            primary_key=True, index=True,
        ),
        sa.Column(
            "scope_id", sa.Integer,
            sa.ForeignKey(
                f"{module_name}__scope.id",
                onupdate="CASCADE", ondelete="CASCADE"
            ),
            primary_key=True, index=True,
        ),
        sa.Column("permission", sa.Text, primary_key=True),
    )
    #
    op.create_table(
        f"{module_name}__token",
        sa.Column("id", sa.Integer, primary_key=True, index=True),
        sa.Column(
            "uuid", sa.String(36),
            index=True, unique=True,
        ),
        sa.Column("expires", sa.DateTime),
        sa.Column(
            "user_id", sa.Integer,
            sa.ForeignKey(
                f"{module_name}__user.id",
                onupdate="CASCADE", ondelete="CASCADE"
            ),
            index=True,
        ),
        sa.Column("name", sa.Text),
    )
    #
    op.create_table(
        f"{module_name}__token_permission",
        sa.Column(
            "token_id", sa.Integer,
            sa.ForeignKey(
                f"{module_name}__token.id",
                onupdate="CASCADE", ondelete="CASCADE"
            ),
            primary_key=True, index=True,
        ),
        sa.Column(
            "scope_id", sa.Integer,
            sa.ForeignKey(
                f"{module_name}__scope.id",
                onupdate="CASCADE", ondelete="CASCADE"
            ),
            primary_key=True, index=True,
        ),
        sa.Column("permission", sa.Text, primary_key=True),
    )

def downgrade(module, payload):
    module_name = module.descriptor.name
    #
    op.drop_table(f"{module_name}__token_permission")
    op.drop_table(f"{module_name}__token")
    op.drop_table(f"{module_name}__group_permission")
    op.drop_table(f"{module_name}__user_permission")
    op.drop_table(f"{module_name}__scope")
    op.drop_table(f"{module_name}__user_group")
    op.drop_table(f"{module_name}__group_provider")
    op.drop_table(f"{module_name}__group")
    op.drop_table(f"{module_name}__user_provider")
    op.drop_table(f"{module_name}__user")
