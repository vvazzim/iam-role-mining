"""Tests for IAM security audit routines."""

from iam_role_mining.data_generator import generate_enterprise_iam_data
from iam_role_mining.ingestion import IAMDataStore
from iam_role_mining.audit import IAMAuditEngine


def test_iam_audit_engine():
    df_id, df_ad, df_app, df_sod = generate_enterprise_iam_data(num_users=100, seed=42)
    store = IAMDataStore(df_id, df_ad, df_app)
    auditor = IAMAuditEngine(store, df_sod)

    findings = auditor.run_full_audit()
    assert len(findings) > 0

    categories = {f.category for f in findings}
    # We should have found at least SoD violations and orphan accounts
    assert "SOD_VIOLATION" in categories
    assert "ORPHAN_ACCOUNT" in categories

    df_findings = auditor.summary_dataframe()
    assert len(df_findings) == len(findings)
    assert "Finding ID" in df_findings.columns
    assert "Severity" in df_findings.columns
