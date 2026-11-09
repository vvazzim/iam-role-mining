"""Tests for synthetic data generation."""

from iam_role_mining.data_generator import generate_enterprise_iam_data


def test_generate_enterprise_iam_data():
    df_id, df_ad, df_app, df_sod = generate_enterprise_iam_data(num_users=50, seed=123)

    assert len(df_id) == 50
    assert "user_id" in df_id.columns
    assert "department" in df_id.columns
    assert "status" in df_id.columns

    assert len(df_ad) > 0
    assert "group_name" in df_ad.columns

    assert len(df_app) > 0
    assert "entitlement_name" in df_app.columns

    assert len(df_sod) >= 3
    assert "entitlement_a" in df_sod.columns
    assert "entitlement_b" in df_sod.columns
