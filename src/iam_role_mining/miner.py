"""
Role Mining Engine (PMR / GM Discovery).
Implements Bottom-Up role discovery and Top-Down organizational alignment
to compute candidate Business Roles (RBAC), coverage ratios, and complexity reduction.
"""

from collections import Counter
from typing import Dict, List, Set, Tuple
import pandas as pd

from iam_role_mining.models import CandidateRole
from iam_role_mining.ingestion import IAMDataStore


class RoleMiningEngine:
    def __init__(self, datastore: IAMDataStore, min_support_ratio: float = 0.65):
        """
        :param datastore: Initialized IAMDataStore
        :param min_support_ratio: Minimum fraction of users in an organizational group
                                  who must hold an entitlement for it to be promoted to the candidate role.
        """
        self.datastore = datastore
        self.min_support_ratio = min_support_ratio
        self.candidate_roles: List[CandidateRole] = []

    def mine_department_roles(self) -> List[CandidateRole]:
        """
        Mines candidate Business Roles (PMR - Profil Métier de Référentiel)
        per department by analyzing frequent entitlement patterns among active users.
        """
        self.candidate_roles = []
        departments = self.datastore.df_identities["department"].unique()

        for dept in sorted(departments):
            dept_active_users = self.datastore.get_department_members(dept, active_only=True)
            num_users = len(dept_active_users)
            if num_users == 0:
                continue

            # Gather all entitlements held by these department members
            entitlement_counts = Counter()
            for uid in dept_active_users:
                user_ents = self.datastore.get_user_entitlements(uid)
                for ent in user_ents:
                    entitlement_counts[ent] += 1

            # Candidate role includes entitlements held by at least min_support_ratio of the team
            support_threshold = max(2, int(num_users * self.min_support_ratio))
            core_entitlements = {
                ent for ent, count in entitlement_counts.items()
                if count >= support_threshold
            }

            if not core_entitlements:
                continue

            # Calculate metrics
            total_dept_assignments = sum(
                len(self.datastore.get_user_entitlements(uid))
                for uid in dept_active_users
            )
            standardized_assignments = len(core_entitlements) * num_users
            # Complexity reduction: percentage of assignments simplified into 1 role
            complexity_score = round(
                (standardized_assignments / max(1, total_dept_assignments)) * 100, 1
            )
            coverage_ratio = round(
                len(core_entitlements) / max(1, len(entitlement_counts)), 3
            )

            role_code = f"PMR_{dept.upper().replace(' ', '_')}"
            candidate = CandidateRole(
                role_id=role_code,
                role_name=f"Rôle Métier Référentiel - {dept}",
                department=dept,
                entitlements=core_entitlements,
                member_user_ids=set(dept_active_users),
                support_count=num_users,
                coverage_ratio=coverage_ratio,
                complexity_score=complexity_score
            )
            self.candidate_roles.append(candidate)

        return self.candidate_roles

    def get_user_role_delta(self, user_id: str, candidate_role: CandidateRole) -> Dict[str, Set[str]]:
        """
        Compares an individual user's current entitlements against a candidate role:
        - missing_entitlements: Rights in the role that the user currently lacks.
        - residual_entitlements: Rights held by the user outside the standard role (atypical/bespoke).
        """
        current_rights = self.datastore.get_user_entitlements(user_id)
        role_rights = candidate_role.entitlements

        missing = role_rights - current_rights
        residual = current_rights - role_rights

        return {
            "assigned_within_role": current_rights.intersection(role_rights),
            "missing_from_role": missing,
            "residual_atypical_rights": residual
        }

    def summary_dataframe(self) -> pd.DataFrame:
        """Exports candidate roles into a presentation-friendly DataFrame."""
        rows = []
        for role in self.candidate_roles:
            rows.append({
                "Role ID": role.role_id,
                "Role Name": role.role_name,
                "Department": role.department,
                "Members Count": role.support_count,
                "Entitlements Count": len(role.entitlements),
                "Entitlement Details": ", ".join(sorted(role.entitlements)),
                "Complexity Reduction (%)": f"{role.complexity_score}%",
                "Department Coverage": f"{round(role.coverage_ratio * 100, 1)}%"
            })
        return pd.DataFrame(rows)
