"""users

Revision ID: f1aaaefd0a65
Revises: 99c2b4f3439a
Create Date: 2022-11-13 15:26:48.568511

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'f1aaaefd0a65'
down_revision = '99c2b4f3439a'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('users',
    sa.Column('user_id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('user_firstname', sa.String(length=120), nullable=False),
    sa.Column('user_lastname', sa.String(length=120), nullable=False),
    sa.Column('user_username', sa.String(length=64), nullable=False),
    sa.Column('password', sa.String(length=128), nullable=False),
    sa.Column('user_created_at', sa.DateTime(), nullable=True),
    sa.Column('user_updated_at', sa.DateTime(), nullable=True),
    sa.Column('admin', sa.Boolean(), nullable=False),
    sa.Column('active', sa.Boolean(), nullable=False),
    sa.Column('verified', sa.Boolean(), nullable=False),
    sa.Column('otp', sa.String(length=16), nullable=True),
    sa.PrimaryKeyConstraint('user_id'),
    sa.UniqueConstraint('otp')
    )
    op.create_index(op.f('ix_users_user_firstname'), 'users', ['user_firstname'], unique=False)
    op.create_index(op.f('ix_users_user_lastname'), 'users', ['user_lastname'], unique=False)
    op.create_index(op.f('ix_users_user_username'), 'users', ['user_username'], unique=True)
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index(op.f('ix_users_user_username'), table_name='users')
    op.drop_index(op.f('ix_users_user_lastname'), table_name='users')
    op.drop_index(op.f('ix_users_user_firstname'), table_name='users')
    op.drop_table('users')
    # ### end Alembic commands ###
