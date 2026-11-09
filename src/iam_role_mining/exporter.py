"""
Audit & Role Mining Exporter.
Produces professional Excel workbooks (multi-tab, styled, pivot-friendly)
and JSON/Markdown executive deliverables.
"""

from pathlib import Path
from typing import Dict, List
import pandas as pd
import openpyxl
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter

from iam_role_mining.models import AuditFinding, CandidateRole
from iam_role_mining.ingestion import IAMDataStore
from iam_role_mining.miner import RoleMiningEngine
from iam_role_mining.audit import IAMAuditEngine


class AuditReportExporter:
    def __init__(
        self,
        datastore: IAMDataStore,
        miner: RoleMiningEngine,
        auditor: IAMAuditEngine
    ):
        self.datastore = datastore
        self.miner = miner
        self.auditor = auditor

    def export_excel_workbook(self, output_path: str) -> str:
        """Generates an executive-grade, multi-tab Excel workbook formatted for audit presentations."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        wb = openpyxl.Workbook()
        # Remove default sheet
        wb.remove(wb.active)

        # Style definitions
        header_fill = PatternFill(start_color="1F497D", end_color="1F497D", fill_type="solid")  # Corporate Navy
        header_font = Font(name="Calibri", size=11, bold=True, color="FFFFFF")
        title_font = Font(name="Calibri", size=14, bold=True, color="1F497D")
        kpi_value_font = Font(name="Calibri", size=18, bold=True, color="1F497D")
        kpi_label_font = Font(name="Calibri", size=10, italic=True, color="595959")
        thin_border = Border(
            left=Side(style='thin', color='D9D9D9'),
            right=Side(style='thin', color='D9D9D9'),
            top=Side(style='thin', color='D9D9D9'),
            bottom=Side(style='thin', color='D9D9D9')
        )

        # -------------------------------------------------------------
        # 1. TAB 1: SYNTHÈSE EXÉCUTIVE
        # -------------------------------------------------------------
        ws_summary = wb.create_sheet(title="Synthese_Executive")
        ws_summary.views.sheetView[0].showGridLines = True

        ws_summary["A1"] = "RAPPORT D'AUDIT IGA & ROLE MINING"
        ws_summary["A1"].font = title_font
        ws_summary["A2"] = "Analyse des habilitations, conformité SoD et modélisation des rôles (PMR / GM)"
        ws_summary["A2"].font = Font(name="Calibri", size=11, italic=True)

        stats = self.datastore.get_identity_summary()
        findings = self.auditor.findings
        sod_count = len([f for f in findings if f.category == "SOD_VIOLATION"])
        orphan_count = len([f for f in findings if f.category == "ORPHAN_ACCOUNT"])
        creep_count = len([f for f in findings if f.category == "PRIVILEGE_CREEP"])
        roles_count = len(self.miner.candidate_roles)

        kpis = [
            ("Total Identités (SIRH)", stats["total_identities"]),
            ("Identités Actives", stats["active_identities"]),
            ("Identités Départs (Leavers)", stats["terminated_identities"]),
            ("Habilitations Uniques", stats["unique_entitlements"]),
            ("Rôles Découverts (PMR)", roles_count),
            ("Violations SoD Critiques", sod_count),
            ("Comptes Orphelins Détectés", orphan_count),
            ("Dérives de Droits (Creep)", creep_count)
        ]

        row = 5
        col = 1
        for label, val in kpis:
            c_val = ws_summary.cell(row=row, column=col, value=val)
            c_val.font = kpi_value_font
            c_val.alignment = Alignment(horizontal="center", vertical="center")
            
            c_lbl = ws_summary.cell(row=row + 1, column=col, value=label)
            c_lbl.font = kpi_label_font
            c_lbl.alignment = Alignment(horizontal="center", vertical="center")
            
            # 2 rows box
            for r in range(row, row + 2):
                ws_summary.cell(row=r, column=col).border = thin_border
                ws_summary.cell(row=r, column=col).fill = PatternFill(start_color="F2F5F9", fill_type="solid")

            col += 1
            if col > 4:
                col = 1
                row += 3

        # -------------------------------------------------------------
        # 2. TAB 2: MODÈLE DE RÔLES (PMR)
        # -------------------------------------------------------------
        ws_roles = wb.create_sheet(title="Modeles_Roles_PMR")
        ws_roles.views.sheetView[0].showGridLines = True
        df_roles = self.miner.summary_dataframe()
        self._write_dataframe_to_sheet(ws_roles, df_roles, header_fill, header_font, thin_border)

        # -------------------------------------------------------------
        # 3. TAB 3: MATRICE DES HABILITATIONS (TCD READY)
        # -------------------------------------------------------------
        ws_matrix = wb.create_sheet(title="Matrice_Habilitations_TCD")
        ws_matrix.views.sheetView[0].showGridLines = True
        
        # Merge identity info with consolidated entitlements for pivot table
        df_tcd = self.datastore.df_consolidated.merge(
            self.datastore.df_identities[["user_id", "first_name", "last_name", "department", "job_title", "status"]],
            on="user_id",
            how="left"
        )
        self._write_dataframe_to_sheet(ws_matrix, df_tcd, header_fill, header_font, thin_border)

        # -------------------------------------------------------------
        # 4. TAB 4: VIOLATIONS SOD
        # -------------------------------------------------------------
        ws_sod = wb.create_sheet(title="Violations_SoD")
        ws_sod.views.sheetView[0].showGridLines = True
        sod_findings = [f for f in findings if f.category == "SOD_VIOLATION"]
        df_sod = pd.DataFrame([
            {
                "Finding ID": f.finding_id,
                "Severity": f.severity,
                "User ID": f.user_id,
                "User Name": f.user_name,
                "Department": f.department,
                "Details": f.details,
                "Remediation": f.remediation
            } for f in sod_findings
        ])
        self._write_dataframe_to_sheet(ws_sod, df_sod, header_fill, header_font, thin_border)

        # -------------------------------------------------------------
        # 5. TAB 5: COMPTES ORPHELINS & DÉRIVES
        # -------------------------------------------------------------
        ws_anomalies = wb.create_sheet(title="Orphelins_et_Derives")
        ws_anomalies.views.sheetView[0].showGridLines = True
        other_findings = [f for f in findings if f.category != "SOD_VIOLATION"]
        df_other = pd.DataFrame([
            {
                "Finding ID": f.finding_id,
                "Category": f.category,
                "Severity": f.severity,
                "User ID": f.user_id,
                "User Name": f.user_name,
                "Department": f.department,
                "Details": f.details,
                "Remediation": f.remediation
            } for f in other_findings
        ])
        self._write_dataframe_to_sheet(ws_anomalies, df_other, header_fill, header_font, thin_border)

        # Auto-adjust column widths on all sheets
        for ws in wb.worksheets:
            for col in ws.columns:
                max_len = 0
                col_letter = get_column_letter(col[0].column)
                for cell in col:
                    if cell.value:
                        val_str = str(cell.value)
                        max_len = max(max_len, min(len(val_str), 55))
                ws.column_dimensions[col_letter].width = max(max_len + 3, 12)

        wb.save(str(path))
        return str(path)

    def _write_dataframe_to_sheet(
        self,
        ws,
        df: pd.DataFrame,
        header_fill,
        header_font,
        border
    ) -> None:
        """Writes a pandas DataFrame into an openpyxl worksheet with formatting."""
        if df.empty:
            ws.cell(row=1, column=1, value="Aucun élément détecté.")
            return

        headers = list(df.columns)
        for col_idx, h in enumerate(headers, start=1):
            cell = ws.cell(row=1, column=col_idx, value=h)
            cell.fill = header_fill
            cell.font = header_font
            cell.alignment = Alignment(horizontal="left", vertical="center")

        for row_idx, row in enumerate(df.itertuples(index=False), start=2):
            for col_idx, val in enumerate(row, start=1):
                cell = ws.cell(row=row_idx, column=col_idx, value=str(val) if isinstance(val, (list, set)) else val)
                cell.border = border
                cell.alignment = Alignment(horizontal="left", vertical="center")
