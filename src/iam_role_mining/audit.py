"""
IAM Security & Compliance Audit Engine.
Detects:
1. Orphan accounts (Terminated identities with active AD/App rights - Leaver anomalies)
2. Segregation of Duties (SoD) toxic entitlement combinations
3. Privilege creep & anomalous inter-departmental rights
4. Highly privileged accounts held by non-authorized profiles
"""

from typing import Dict, List, Set
import pandas as pd

from iam_role_mining.models import AuditFinding, SoDRule
from iam_role_mining.ingestion import IAMDataStore


class IAMAuditEngine:
    def __init__(self, datastore: IAMDataStore, df_sod_rules: pd.DataFrame):
        self.datastore = datastore
        self.df_sod_rules = df_sod_rules.copy()
        self.findings: List[AuditFinding] = []

    def run_full_audit(self) -> List[AuditFinding]:
        """Runs all automated audit routines and returns consolidated findings."""
        self.findings = []
        self._audit_orphan_accounts()
        self._audit_sod_violations()
        self._audit_privilege_creep()
        self._audit_overprivileged_accounts()
        return self.findings

    def _audit_orphan_accounts(self) -> None:
        """Flags users terminated in HR who still hold permissions in AD or Apps."""
        terminated_users = self.datastore.df_identities[
            self.datastore.df_identities["status"] == "TERMINATED"
        ]

        counter = 1
        for _, user in terminated_users.iterrows():
            uid = user["user_id"]
            user_ents = self.datastore.get_user_entitlements(uid)
            if user_ents:
                finding = AuditFinding(
                    finding_id=f"ORPHAN-{counter:03d}",
                    category="ORPHAN_ACCOUNT",
                    user_id=uid,
                    user_name=f"{user['first_name']} {user['last_name']}",
                    department=user["department"],
                    severity="CRITICAL",
                    details=(
                        f"Compte orphelin actif : L'utilisateur est noté 'TERMINATED' dans le SIRH "
                        f"mais conserve {len(user_ents)} habilitations actives ({', '.join(sorted(list(user_ents)[:4]))}...). "
                        f"Processus Leaver non appliqué."
                    ),
                    remediation="Révocation immédiate de tous les accès Active Directory et comptes applicatifs associés."
                )
                self.findings.append(finding)
                counter += 1

    def _audit_sod_violations(self) -> None:
        """Evaluates all users against the Segregation of Duties (SoD) toxic rules matrix."""
        counter = 1
        for _, rule in self.df_sod_rules.iterrows():
            ent_a = rule["entitlement_a"]
            ent_b = rule["entitlement_b"]
            rule_id = rule["rule_id"]
            risk_level = rule["risk_level"]

            # Filter active users holding both entitlements
            for _, user in self.datastore.df_identities.iterrows():
                uid = user["user_id"]
                user_ents = self.datastore.get_user_entitlements(uid)

                if ent_a in user_ents and ent_b in user_ents:
                    finding = AuditFinding(
                        finding_id=f"SOD-{counter:03d}",
                        category="SOD_VIOLATION",
                        user_id=uid,
                        user_name=f"{user['first_name']} {user['last_name']}",
                        department=user["department"],
                        severity=risk_level,
                        details=(
                            f"Violation SoD [{rule_id}] : L'utilisateur détient simultanément les droits conflictuels "
                            f"'{ent_a}' et '{ent_b}'. {rule['description']}"
                        ),
                        remediation=(
                            f"Retirer l'un des deux droits ({ent_a} ou {ent_b}) pour rétablir le principe "
                            f"de double regard ou documenter un contrôle compensatoire validé par le RSSI / Risques."
                        )
                    )
                    self.findings.append(finding)
                    counter += 1

    def _audit_privilege_creep(self) -> None:
        """
        Flags users who hold entitlements belonging to departments other than their current one
        (typically indicating a job change / Mover where old privileges were not revoked).
        """
        dept_signatures = {
            "Finance": "FINANCE",
            "Human Resources": "HR",
            "Engineering": "IT",
            "Sales": "SALES",
            "Legal": "LEGAL"
        }

        counter = 1
        for _, user in self.datastore.df_identities.iterrows():
            if user["status"] != "ACTIVE":
                continue

            uid = user["user_id"]
            dept = user["department"]
            user_ents = self.datastore.get_user_entitlements(uid)

            alien_rights = []
            for ent in user_ents:
                for other_dept, keyword in dept_signatures.items():
                    if other_dept != dept and keyword in ent:
                        alien_rights.append((ent, other_dept))

            if alien_rights:
                detail_str = ", ".join([f"{ent} (dédié {d})" for ent, d in alien_rights])
                finding = AuditFinding(
                    finding_id=f"CREEP-{counter:03d}",
                    category="PRIVILEGE_CREEP",
                    user_id=uid,
                    user_name=f"{user['first_name']} {user['last_name']}",
                    department=dept,
                    severity="HIGH",
                    details=(
                        f"Accumulation anormale de droits (Privilege Creep) : Salarié du département '{dept}' "
                        f"détenant des privilèges étrangers : {detail_str}. Signe d'une mobilité interne sans dé-provisionnement."
                    ),
                    remediation="Lancer une revue d'habilitation Mover avec le manager pour révoquer les accès de l'ancien poste."
                )
                self.findings.append(finding)
                counter += 1

    def _audit_overprivileged_accounts(self) -> None:
        """Flags non-IT accounts holding Domain Admin or highly sensitive system privileges."""
        sensitive_groups = ["GG_SEC_DOMAIN_ADMINS", "AWS_PROD_ADMIN"]
        counter = 1

        for _, user in self.datastore.df_identities.iterrows():
            if user["status"] != "ACTIVE" or user["department"] == "Engineering":
                continue

            uid = user["user_id"]
            user_ents = self.datastore.get_user_entitlements(uid)
            held_sensitive = user_ents.intersection(set(sensitive_groups))

            if held_sensitive:
                finding = AuditFinding(
                    finding_id=f"OVERPRIV-{counter:03d}",
                    category="OVER_PRIVILEGED",
                    user_id=uid,
                    user_name=f"{user['first_name']} {user['last_name']}",
                    department=user["department"],
                    severity="CRITICAL",
                    details=(
                        f"Compte métier hautement privilégié : Utilisateur du département '{user['department']}' "
                        f"détient un droit d'administration système : {', '.join(held_sensitive)}."
                    ),
                    remediation="Révocation immédiate du compte à privilèges et alignement strict sur le principe de moindre privilège."
                )
                self.findings.append(finding)
                counter += 1

    def summary_dataframe(self) -> pd.DataFrame:
        """Exports audit findings into a clean DataFrame."""
        rows = []
        for f in self.findings:
            rows.append({
                "Finding ID": f.finding_id,
                "Category": f.category,
                "Severity": f.severity,
                "User ID": f.user_id,
                "User Name": f.user_name,
                "Department": f.department,
                "Finding Details": f.details,
                "Recommended Action": f.remediation
            })
        return pd.DataFrame(rows)
