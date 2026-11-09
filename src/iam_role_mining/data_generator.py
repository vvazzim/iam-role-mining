"""
Synthetic Enterprise IAM Dataset Generator.
Generates realistic identity records, Active Directory groups, application entitlements,
and plants classic audit anomalies (Orphan accounts, SoD conflicts, privilege creep).
"""

import random
from typing import Dict, List, Tuple
import pandas as pd


def generate_enterprise_iam_data(
    num_users: int = 120,
    seed: int = 42
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """
    Generates 4 DataFrames:
    1. df_identities (HR Reference)
    2. df_ad_memberships (Active Directory group memberships)
    3. df_app_entitlements (Application-level entitlements)
    4. df_sod_rules (Segregation of Duties rules)
    """
    random.seed(seed)

    first_names = ["Alexandre", "Camille", "Thomas", "Sarah", "Julien", "Lea", "Nicolas", "Emma",
                   "Maxime", "Chloe", "Antoine", "Ines", "Lucas", "Manon", "Hugo", "Jade",
                   "Gabriel", "Louise", "Arthur", "Alice", "Raphael", "Lina", "Wassim", "Amine"]
    last_names = ["Dubois", "Moreau", "Laurent", "Simon", "Michel", "Lefebvre", "Leroy", "Roux",
                  "David", "Bertrand", "Morel", "Fournier", "Girard", "Bonnet", "Dupont", "Fontaine",
                  "Lambert", "Faure", "Rousseau", "Vincent", "Muller", "Guerin", "Boyer", "Garnier"]

    departments = {
        "Finance": ["Financial Analyst", "Accountant", "Billing Specialist", "Finance Director"],
        "Human Resources": ["HR Generalist", "Payroll Specialist", "Recruiter", "HR Director"],
        "Engineering": ["Software Engineer", "DevOps Engineer", "Data Engineer", "Tech Lead"],
        "Sales": ["Account Executive", "Sales Representative", "Customer Success", "Sales Manager"],
        "Legal": ["Legal Counsel", "Compliance Officer", "DPO Assistant", "General Counsel"]
    }

    # Department default entitlements mapping
    dept_ad_groups = {
        "Finance": ["GG_SEC_CORP_VPN", "GG_SEC_FINANCE_USERS", "GG_SEC_OFFICE365_E5"],
        "Human Resources": ["GG_SEC_CORP_VPN", "GG_SEC_HR_USERS", "GG_SEC_OFFICE365_E5"],
        "Engineering": ["GG_SEC_CORP_VPN", "GG_SEC_IT_DEV_USERS", "GG_SEC_OFFICE365_E5", "GG_SEC_GITLAB_USERS"],
        "Sales": ["GG_SEC_CORP_VPN", "GG_SEC_SALES_USERS", "GG_SEC_OFFICE365_E5"],
        "Legal": ["GG_SEC_CORP_VPN", "GG_SEC_LEGAL_USERS", "GG_SEC_OFFICE365_E5"]
    }

    dept_apps = {
        "Finance": ["SAP_FI_GENERAL_LEDGER", "SAP_FI_REPORTING_VIEWER"],
        "Human Resources": ["WORKDAY_EMPLOYEE_READ", "PAYFIT_VIEWER"],
        "Engineering": ["AWS_DEV_CONTRIBUTOR", "DATADOG_READONLY", "GITHUB_READ_WRITE"],
        "Sales": ["SALESFORCE_CORE_USER", "HUBSPOT_STANDARD_CRM"],
        "Legal": ["DOCUSIGN_STANDARD_SENDER", "LEGAL_ARCHIVE_VIEWER"]
    }

    # Generate HR Identities
    identities = []
    used_emails = set()

    dept_keys = list(departments.keys())
    for i in range(1, num_users + 1):
        dept = random.choice(dept_keys)
        title = random.choice(departments[dept])
        fn = random.choice(first_names)
        ln = random.choice(last_names)
        uid = f"U{i:04d}"
        
        email_base = f"{fn.lower()}.{ln.lower()}"
        email = f"{email_base}@entreprise-demo.fr"
        counter = 1
        while email in used_emails:
            email = f"{email_base}{counter}@entreprise-demo.fr"
            counter += 1
        used_emails.add(email)

        # 90% ACTIVE, 10% TERMINATED (Leavers)
        status = "TERMINATED" if random.random() < 0.10 else "ACTIVE"

        identities.append({
            "user_id": uid,
            "first_name": fn,
            "last_name": ln,
            "email": email,
            "department": dept,
            "job_title": title,
            "manager_id": f"U{random.randint(1, 10):04d}",
            "status": status,
            "contract_type": "CDI" if random.random() < 0.85 else "PRESTATAIRE"
        })

    df_identities = pd.DataFrame(identities)

    # Generate AD Group Memberships & Application Entitlements
    ad_memberships = []
    app_entitlements = []

    for _, row in df_identities.iterrows():
        uid = row["user_id"]
        dept = row["department"]
        status = row["status"]

        # Base entitlements assigned by role
        ad_groups = list(dept_ad_groups[dept])
        apps = list(dept_apps[dept])

        # Random noise: 15% have an extra generic group
        if random.random() < 0.15:
            ad_groups.append("GG_SEC_PROJECT_ALPHA_CONTRIBUTORS")

        # Specific job title additions
        if "Director" in row["job_title"] or "Lead" in row["job_title"]:
            ad_groups.append(f"GG_SEC_{dept.upper()[:3]}_MANAGERS")
            apps.append("BI_POWERBI_PRO_EXECUTIVE")

        if row["job_title"] == "Accountant":
            apps.append("SAP_FI_INVOICE_CREATE")
        elif row["job_title"] == "Billing Specialist":
            apps.append("SAP_FI_PAYMENT_RUN")

        if row["job_title"] == "Payroll Specialist":
            apps.append("PAYFIT_PAYROLL_ADMIN")

        if row["job_title"] == "DevOps Engineer":
            ad_groups.append("GG_SEC_IT_INFRA_ADMINS")
            apps.append("AWS_PROD_DEPLOYER")

        # Planted Anomaly 1: Orphan Accounts (Terminated users still holding groups & apps)
        if status == "TERMINATED":
            # 60% of terminated users were NOT deprovisioned properly!
            if random.random() < 0.60:
                for grp in ad_groups:
                    ad_memberships.append({"user_id": uid, "group_name": grp, "assigned_system": "ActiveDirectory"})
                for app in apps:
                    app_entitlements.append({"user_id": uid, "entitlement_name": app, "target_application": app.split("_")[0]})
            continue

        # Active users normal assignment
        for grp in ad_groups:
            ad_memberships.append({"user_id": uid, "group_name": grp, "assigned_system": "ActiveDirectory"})
        for app in apps:
            app_entitlements.append({"user_id": uid, "entitlement_name": app, "target_application": app.split("_")[0]})

    # Planted Anomaly 2: Segregation of Duties (SoD) Violations
    # Give 3 Finance users both Invoice Create AND Payment Approve
    finance_users = df_identities[(df_identities["department"] == "Finance") & (df_identities["status"] == "ACTIVE")]["user_id"].tolist()
    for uid in finance_users[:3]:
        app_entitlements.append({"user_id": uid, "entitlement_name": "SAP_FI_INVOICE_CREATE", "target_application": "SAP"})
        app_entitlements.append({"user_id": uid, "entitlement_name": "SAP_FI_PAYMENT_APPROVE", "target_application": "SAP"})

    # Planted Anomaly 3: Privilege Creep (User moved from Engineering to Sales, kept AWS/DevOps rights)
    sales_users = df_identities[(df_identities["department"] == "Sales") & (df_identities["status"] == "ACTIVE")]["user_id"].tolist()
    if sales_users:
        mover_uid = sales_users[0]
        ad_memberships.append({"user_id": mover_uid, "group_name": "GG_SEC_IT_DEV_USERS", "assigned_system": "ActiveDirectory"})
        app_entitlements.append({"user_id": mover_uid, "entitlement_name": "AWS_DEV_CONTRIBUTOR", "target_application": "AWS"})
        app_entitlements.append({"user_id": mover_uid, "entitlement_name": "GITHUB_READ_WRITE", "target_application": "GITHUB"})

    # Planted Anomaly 4: Over-privileged non-IT account
    hr_users = df_identities[(df_identities["department"] == "Human Resources") & (df_identities["status"] == "ACTIVE")]["user_id"].tolist()
    if hr_users:
        overpriv_uid = hr_users[0]
        ad_memberships.append({"user_id": overpriv_uid, "group_name": "GG_SEC_DOMAIN_ADMINS", "assigned_system": "ActiveDirectory"})

    df_ad_memberships = pd.DataFrame(ad_memberships).drop_duplicates()
    df_app_entitlements = pd.DataFrame(app_entitlements).drop_duplicates()

    # SoD Rules Matrix
    sod_rules = [
        {
            "rule_id": "SOD_FIN_001",
            "rule_name": "Création de facture & Approbation de paiement",
            "entitlement_a": "SAP_FI_INVOICE_CREATE",
            "entitlement_b": "SAP_FI_PAYMENT_APPROVE",
            "risk_level": "CRITICAL",
            "description": "Risque majeur de détournement de fonds : une même identité peut créer un fournisseur/facture et valider le paiement sans double regard."
        },
        {
            "rule_id": "SOD_HR_002",
            "rule_name": "Gestion des salariés & Exécution de la paie",
            "entitlement_a": "WORKDAY_EMPLOYEE_READ",
            "entitlement_b": "PAYFIT_PAYROLL_ADMIN",
            "risk_level": "HIGH",
            "description": "Risque de création d'employé fantôme et d'émission de virement de salaire non contrôlé."
        },
        {
            "rule_id": "SOD_IT_003",
            "rule_name": "Développement applicatif & Déploiement direct en production",
            "entitlement_a": "GITHUB_READ_WRITE",
            "entitlement_b": "AWS_PROD_DEPLOYER",
            "risk_level": "MEDIUM",
            "description": "Non-respect de la séparation Dev/Ops : risque d'injection de code non revu directement sur l'infrastructure de production."
        }
    ]
    df_sod_rules = pd.DataFrame(sod_rules)

    return df_identities, df_ad_memberships, df_app_entitlements, df_sod_rules
