"""
Streamlit Web Application: IAM / IGA Role Mining & Security Audit Console.
Designed for IAM consultants, security auditors, and client presentations.
"""

import io
import streamlit as st
import pandas as pd

from iam_role_mining.data_generator import generate_enterprise_iam_data
from iam_role_mining.ingestion import IAMDataStore
from iam_role_mining.miner import RoleMiningEngine
from iam_role_mining.audit import IAMAuditEngine
from iam_role_mining.exporter import AuditReportExporter

st.set_page_config(
    page_title="Console IAM / IGA & Role Mining",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Console de Profilage IAM / IGA & Role Mining")
st.markdown(
    "**Analyse des matrices d'habilitations, modélisation des profils métiers (PMR / GM), "
    "contrôles de Séparation des Tâches (SoD) et détection des comptes orphelins.**"
)

# Sidebar Controls
st.sidebar.header("Paramètres d'Audit")
num_users = st.sidebar.slider("Nombre d'identités à simuler", min_value=50, max_value=300, value=120, step=10)
min_support = st.sidebar.slider("Seuil d'éligibilité au rôle (%)", min_value=50, max_value=90, value=65, step=5) / 100.0

if st.sidebar.button("🔄 Régénérer les Données & Relancer l'Audit"):
    st.cache_data.clear()

@st.cache_data
def load_and_process_data(n_users: int, support: float):
    df_id, df_ad, df_app, df_sod = generate_enterprise_iam_data(num_users=n_users)
    datastore = IAMDataStore(df_id, df_ad, df_app)
    miner = RoleMiningEngine(datastore, min_support_ratio=support)
    roles = miner.mine_department_roles()
    auditor = IAMAuditEngine(datastore, df_sod)
    findings = auditor.run_full_audit()
    return datastore, miner, auditor, df_sod

datastore, miner, auditor, df_sod = load_and_process_data(num_users, min_support)

# Top KPI Row
stats = datastore.get_identity_summary()
findings = auditor.findings
sod_count = len([f for f in findings if f.category == "SOD_VIOLATION"])
orphan_count = len([f for f in findings if f.category == "ORPHAN_ACCOUNT"])
creep_count = len([f for f in findings if f.category == "PRIVILEGE_CREEP"])

col1, col2, col3, col4, col5 = st.columns(5)
col1.metric("Total Identités (SIRH)", stats["total_identities"], delta=f"{stats['active_identities']} actives")
col2.metric("Rôles Découverts (PMR)", len(miner.candidate_roles))
col3.metric("Violations SoD", sod_count, delta="Risque Audit", delta_color="inverse")
col4.metric("Comptes Orphelins", orphan_count, delta="Leavers non traités", delta_color="inverse")
col5.metric("Dérives de Droits", creep_count, delta="Privilege Creep", delta_color="inverse")

st.divider()

# Main Tabs
tab_roles, tab_matrix, tab_sod, tab_orphans, tab_export = st.tabs([
    "📋 Modèles de Rôles (PMR / GM)",
    "📊 Matrice d'Habilitations (TCD)",
    "⚠️ Séparation des Tâches (SoD)",
    "🚨 Comptes Orphelins & Dérives",
    "💾 Export Livrable Excel"
])

# 1. Modèles de Rôles
with tab_roles:
    st.subheader("Rôles Métiers Référentiels (PMR) découverts par Département")
    df_roles = miner.summary_dataframe()
    st.dataframe(df_roles, use_container_width=True)

    st.markdown("### Analyse détaillée d'un profil")
    selected_role_id = st.selectbox("Sélectionner un rôle à auditer", [r.role_id for r in miner.candidate_roles])
    target_role = next(r for r in miner.candidate_roles if r.role_id == selected_role_id)

    st.write(f"**Département :** {target_role.department} | **Membres couverts :** {target_role.support_count}")
    st.write("**Panier d'habilitations du rôle :**")
    st.code("\n".join([f"- {ent}" for ent in sorted(target_role.entitlements)]))

# 2. Matrice d'Habilitations
with tab_matrix:
    st.subheader("Vue Tabulaire pour Tableau Croisé Dynamique (TCD)")
    dept_filter = st.multiselect("Filtrer par Département", datastore.df_identities["department"].unique())

    df_display = datastore.df_consolidated.merge(
        datastore.df_identities[["user_id", "first_name", "last_name", "department", "job_title", "status"]],
        on="user_id",
        how="left"
    )
    if dept_filter:
        df_display = df_display[df_display["department"].isin(dept_filter)]

    st.dataframe(df_display, use_container_width=True, height=450)

# 3. Séparation des Tâches (SoD)
with tab_sod:
    st.subheader("Violations de Séparation des Tâches Détectées")
    sod_findings = [f for f in findings if f.category == "SOD_VIOLATION"]
    if sod_findings:
        df_sod_res = pd.DataFrame([
            {
                "ID": f.finding_id,
                "Sévérité": f.severity,
                "Utilisateur": f.user_name,
                "Département": f.department,
                "Détail de la Violation": f.details,
                "Action Recommandée": f.remediation
            } for f in sod_findings
        ])
        st.dataframe(df_sod_res, use_container_width=True)
    else:
        st.success("Aucune violation SoD détectée.")

# 4. Comptes Orphelins & Dérives
with tab_orphans:
    st.subheader("Anomalies du Cycle de Vie des Identités (Joiner / Mover / Leaver)")
    other_findings = [f for f in findings if f.category != "SOD_VIOLATION"]
    if other_findings:
        df_other = pd.DataFrame([
            {
                "ID": f.finding_id,
                "Catégorie": f.category,
                "Sévérité": f.severity,
                "Salarié": f.user_name,
                "Département": f.department,
                "Constat d'Audit": f.details,
                "Remédiation Immédiate": f.remediation
            } for f in other_findings
        ])
        st.dataframe(df_other, use_container_width=True)
    else:
        st.success("Aucun compte orphelin ou dérive détecté.")

# 5. Export Livrable
with tab_export:
    st.subheader("Génération du Classeur Excel d'Audit")
    st.write(
        "Ce classeur contient la synthèse exécutive, les profils PMR découverts, "
        "la matrice d'habilitations brute prête pour vos TCD, ainsi que le plan de remédiation SoD."
    )

    temp_path = "data/output/temp_export.xlsx"
    exporter = AuditReportExporter(datastore, miner, auditor)
    exporter.export_excel_workbook(temp_path)

    with open(temp_path, "rb") as f:
        excel_bytes = f.read()

    st.download_button(
        label="📥 Télécharger le Rapport Excel Complet (.xlsx)",
        data=excel_bytes,
        file_name="Audit_IAM_Role_Mining_Wassim_CHIKHI.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )
