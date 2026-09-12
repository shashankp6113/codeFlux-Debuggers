"""Add unique constraint to emails

Revision ID: c6547c73a3ec
Revises: a3d7f1e92c48
Create Date: 2026-09-12 09:45:35.086180

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c6547c73a3ec'
down_revision: Union[str, Sequence[str], None] = 'a3d7f1e92c48'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Use batch operation for SQLite compatibility if ever needed, 
    # but Postgres supports create_unique_constraint directly.
    op.create_unique_constraint('uq_email_account_message', 'emails', ['email_account_id', 'message_id'])


def downgrade() -> None:
    op.drop_constraint('uq_email_account_message', 'emails', type_='unique')
