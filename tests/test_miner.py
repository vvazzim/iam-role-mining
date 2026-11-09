"""Tests for role mining and candidate role extraction."""

from iam_role_mining.data_generator import generate_enterprise_iam_data
from iam_role_mining.ingestion import IAMDataStore
from iam_role_mining.miner import RoleMiningEngine


def test_role_mining_engine():
    df_id, df_ad, df_app, _ = generate_enterprise_iam_data(num_users=60, seed=42)
    store = IAMDataStore(df_id, df_ad, df_app)
    miner = RoleMiningEngine(store, min_support_ratio=0.60)

    roles = miner.mine_department_roles()
    assert len(roles) > 0

    for role in roles:
        assert role.role_id.startswith("PMR_")
        assert len(role.entitlements) > 0
        assert role.support_count > 0

    df_summary = miner.summary_dataframe()
    assert len(df_summary) == len(roles)
    assert "Role ID" in df_summary.columns
