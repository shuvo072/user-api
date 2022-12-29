"""Jobs Table added

Revision ID: 2e33f4254c4a
Revises: e4c011688fa8
Create Date: 2022-11-14 16:47:20.892151

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '2e33f4254c4a'
down_revision = 'e4c011688fa8'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('jobs',
    sa.Column('job_id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('job_title', sa.String(length=120), nullable=False),
    sa.Column('company_name', sa.String(length=120), nullable=False),
    sa.Column('start_year', sa.String(length=5), nullable=False),
    sa.Column('end_year', sa.String(length=5), nullable=True),
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['users.user_id'], ),
    sa.PrimaryKeyConstraint('job_id')
    )
    op.create_index(op.f('ix_jobs_company_name'), 'jobs', ['company_name'], unique=False)
    op.create_index(op.f('ix_jobs_job_title'), 'jobs', ['job_title'], unique=False)
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index(op.f('ix_jobs_job_title'), table_name='jobs')
    op.drop_index(op.f('ix_jobs_company_name'), table_name='jobs')
    op.drop_table('jobs')
    # ### end Alembic commands ###