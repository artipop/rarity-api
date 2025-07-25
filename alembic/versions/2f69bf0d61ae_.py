"""empty message

Revision ID: 2f69bf0d61ae
Revises: ec562f9984c4
Create Date: 2025-07-07 14:52:10.204883

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '2f69bf0d61ae'
down_revision: Union[str, None] = 'ec562f9984c4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('manufacturer_cities',
    sa.Column('manufacturer_id', sa.Integer(), nullable=False),
    sa.Column('city_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['city_id'], ['cities.id'], ),
    sa.ForeignKeyConstraint(['manufacturer_id'], ['manufacturers.id'], ),
    sa.PrimaryKeyConstraint('manufacturer_id', 'city_id')
    )
    op.drop_table('manufacturer_city')
    # ### end Alembic commands ###


def downgrade() -> None:
    """Downgrade schema."""
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('manufacturer_city',
    sa.Column('manufacturer_id', sa.INTEGER(), autoincrement=False, nullable=False),
    sa.Column('city_id', sa.INTEGER(), autoincrement=False, nullable=False),
    sa.ForeignKeyConstraint(['city_id'], ['cities.id'], name=op.f('manufacturer_city_city_id_fkey')),
    sa.ForeignKeyConstraint(['manufacturer_id'], ['manufacturers.id'], name=op.f('manufacturer_city_manufacturer_id_fkey')),
    sa.PrimaryKeyConstraint('manufacturer_id', 'city_id', name=op.f('manufacturer_city_pkey'))
    )
    op.drop_table('manufacturer_cities')
    # ### end Alembic commands ###
