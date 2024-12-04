#!/usr/bin/python3
# coding=utf-8


"""Add monitor role

Revision ID: 202412021300
Revises:
Create Date: 2024-12-02 13:39:37.784522

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '202412021300'
down_revision = "202202021633"
branch_labels = None
depends_on = None

role_name = "monitor"
role_mode = "default"

def upgrade(module, payload):
    module_name = module.descriptor.name

    op.execute(
        sa.text(
            f"""
            INSERT INTO {module_name}__role (name, mode) 
            VALUES (:name, :mode)
            """
        ).bindparams(**{"name": role_name, "mode": role_mode})
    )


def downgrade(module, payload):
    module_name = module.descriptor.name

    op.execute(
        sa.text(
            f"""
            DELETE FROM {module_name}__role
            WHERE name = :name AND mode = :mode
            """
        ).bindparams(**{"name": role_name, "mode": role_mode})
    )
