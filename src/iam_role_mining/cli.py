"""
Command Line Interface for IAM Role Mining & Security Audit.
Usage:
    python -m iam_role_mining.cli run-all
"""

import argparse
import json
from pathlib import Path
import sys

from iam_role_mining.data_generator import generate_enterprise_iam_data
from iam_role_mining.ingestion import IAMDataStore
from iam_role_mining.miner import RoleMiningEngine
from iam_role_mining.audit import IAMAuditEngine
from iam_role_mining.exporter import AuditReportExporter


def main():
    parser = argparse.ArgumentParser(
        description="Enterprise IAM / IGA Role Mining & Security Audit CLI"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Command: run-all
    parser_run = subparsers.add_parser("run-all", help="Generate demo data, run mining, audit, and export Excel report")
    parser_run.add_argument("--users", type=int, default=120, help="Number of synthetic users to generate")
    parser_run.add_argument("--output-dir", type=str, default="data/output", help="Output directory for reports")

    args = parser.parse_args()

    if args.command in (None, "run-all"):
        output_dir = Path("data/output")
        output_dir.mkdir(parents=True, exist_ok=True)
        excel_path = output_dir / "role_mining_audit_report.xlsx"

        print("=" * 80)
        print(" [IAM / IGA] ROLE MINING & AUDIT ENGINE --- DÉMARRAGE DE L'ANALYSE")
        print("=" * 80)

        # 1. Data Generation
        print("\n[1/4] Génération des jeux de données d'accès d'entreprise...")
        df_id, df_ad, df_app, df_sod = generate_enterprise_iam_data(num_users=120)
        print(f" -> {len(df_id)} identités créées (SIRH)")
        print(f" -> {len(df_ad)} adhésions de groupes Active Directory")
        print(f" -> {len(df_app)} habilitations applicatives (SAP, AWS, Salesforce, etc.)")
        print(f" -> {len(df_sod)} règles de séparation des tâches (SoD) configurées")

        # 2. Ingestion & Consolidation
        print("\n[2/4] Consolidation de la matrice Utilisateur x Habilitations...")
        datastore = IAMDataStore(df_id, df_ad, df_app)
        stats = datastore.get_identity_summary()
        print(f" -> {stats['active_identities']} identités actives traitées")
        print(f" -> {stats['unique_entitlements']} habilitations uniques consolidées")
        print(f" -> Matrice binaire construite : dimension {datastore.matrix.shape}")

        # 3. Role Mining (PMR / GM)
        print("\n[3/4] Exécution de l'algorithme de Role Mining (PMR - Profils Métiers)...")
        miner = RoleMiningEngine(datastore, min_support_ratio=0.65)
        roles = miner.mine_department_roles()
        for r in roles:
            print(f"  [*] {r.role_id} : {len(r.entitlements)} habilitations | {r.support_count} membres couverts ({r.complexity_score}% réduction complexité)")

        # 4. Security & Compliance Audit
        print("\n[4/4] Exécution de l'Audit de Sécurité & Conformité IGA...")
        auditor = IAMAuditEngine(datastore, df_sod)
        findings = auditor.run_full_audit()

        sod_count = len([f for f in findings if f.category == "SOD_VIOLATION"])
        orphan_count = len([f for f in findings if f.category == "ORPHAN_ACCOUNT"])
        creep_count = len([f for f in findings if f.category == "PRIVILEGE_CREEP"])
        overpriv_count = len([f for f in findings if f.category == "OVER_PRIVILEGED"])

        print(f"  [!] {sod_count} Violations de Séparation des Tâches (SoD)")
        print(f"  [!] {orphan_count} Comptes Orphelins (Salariés partis non déprovisionnés)")
        print(f"  [!] {creep_count} Cas d'accumulation anormale de droits (Privilege Creep)")
        print(f"  [!] {overpriv_count} Comptes à privilèges excessifs non autorisés")

        # 5. Export
        exporter = AuditReportExporter(datastore, miner, auditor)
        generated_file = exporter.export_excel_workbook(str(excel_path))

        print("\n" + "=" * 80)
        print(f" [SUCCÈS] Classeur Excel d'audit généré : {generated_file}")
        print(" Feuilles disponibles :")
        print("  - Synthese_Executive (KPIs et métriques clés)")
        print("  - Modeles_Roles_PMR (Définitions formelles des profils)")
        print("  - Matrice_Habilitations_TCD (Prêt pour Tableaux Croisés Dynamiques)")
        print("  - Violations_SoD (Détails des conflits de pouvoirs)")
        print("  - Orphelins_et_Derives (Comptes à révoquer d'urgence)")
        print("=" * 80)


if __name__ == "__main__":
    main()
