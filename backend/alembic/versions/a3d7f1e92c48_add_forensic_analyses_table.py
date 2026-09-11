"""add forensic_analyses table

Revision ID: a3d7f1e92c48
Revises: cfce780d61b5
Create Date: 2026-09-11 03:05:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = 'a3d7f1e92c48'
down_revision: Union[str, None] = 'cfce780d61b5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'forensic_analyses',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('email_id', sa.Integer(), nullable=False),
        sa.Column('analysis', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['email_id'], ['emails.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('email_id'),
    )
    op.create_index(op.f('ix_forensic_analyses_id'), 'forensic_analyses', ['id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_forensic_analyses_id'), table_name='forensic_analyses')
    op.drop_table('forensic_analyses')
