"""add performance indexes

Revision ID: d985a1b32d56
Revises: c6547c73a3ec
Create Date: 2026-09-13 04:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd985a1b32d56'
down_revision: Union[str, None] = 'c6547c73a3ec'  # Wait, what's the actual head? I'll check below
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    # We add indexes to EmailAccount.user_id and Email.received_at
    op.create_index(op.f('ix_email_accounts_user_id'), 'email_accounts', ['user_id'], unique=False)
    op.create_index(op.f('ix_emails_received_at'), 'emails', ['received_at'], unique=False)

def downgrade() -> None:
    op.drop_index(op.f('ix_emails_received_at'), table_name='emails')
    op.drop_index(op.f('ix_email_accounts_user_id'), table_name='email_accounts')
