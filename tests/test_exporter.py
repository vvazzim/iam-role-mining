"""Tests for multi-tab Excel export."""

from pathlib import Path
import openpyxl

from iam_role_mining.data_generator import generate_enterprise_iam_data
from iam_role_mining.ingestion import IAMDataStore
from iam_role_mining.miner import RoleMiningEngine
from iam_role_mining.audit import IAMAuditEngine
from iam_role_mining.exporter import AuditReportExporter


def test_excel_export(tmp_path: Path):
    df_id, df_ad, df_app, df_sod = generate_enterprise_iam_data(num_users=40, seed=42)
    store = IAMDataStore(df_id, df_ad, df_app)
    miner = RoleMiningEngine(store, min_support_ratio=0.60)
    miner.mine_department_roles()
    auditor = IAMAuditEngine(store, df_sod)
    auditor.run_full_audit()

    out_file = tmp_path / "test_report.xlsx"
    exporter = AuditReportExporter(store, miner, auditor)
    res_path = exporter.export_excel_workbook(str(out_file))

    assert Path(res_path).exists()
    wb = openpyxl.load_workbook(res_path)
    sheet_names = wb.sheetnames
    assert "Synthese_Executive" in sheet_names
    assert "Modeles_Roles_PMR" in sheet_names
    assert "Matrice_Habilitations_TCD" in sheet_names
    assert "Violations_SoD" in sheet_names
    assert "Orphelins_et_Derives" in sheet_names
