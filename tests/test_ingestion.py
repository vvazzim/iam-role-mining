"""Tests for IAM data ingestion and matrix construction."""

from iam_role_mining.data_generator import generate_enterprise_iam_data
from iam_role_mining.ingestion import IAMDataStore


def test_iam_data_store():
    df_id, df_ad, df_app, _ = generate_enterprise_iam_data(num_users=30, seed=42)
    store = IAMDataStore(df_id, df_ad, df_app)

    stats = store.get_identity_summary()
    assert stats["total_identities"] == 30
    assert stats["unique_entitlements"] > 0
    assert store.matrix.shape[0] <= 30
    assert store.matrix.shape[1] == stats["unique_entitlements"]

    user_sample = df_id.iloc[0]["user_id"]
    ents = store.get_user_entitlements(user_sample)
    assert isinstance(ents, set)
