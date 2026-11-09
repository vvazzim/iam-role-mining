"""
Data Ingestion & Consolidation Engine.
Normalizes, joins, and transforms raw identity and access data into a unified
user-entitlement matrix ready for role mining and security audits.
"""

from typing import Dict, List, Set, Tuple
import pandas as pd


class IAMDataStore:
    def __init__(
        self,
        df_identities: pd.DataFrame,
        df_ad_memberships: pd.DataFrame,
        df_app_entitlements: pd.DataFrame
    ):
        self.df_identities = df_identities.copy()
        self.df_ad_memberships = df_ad_memberships.copy()
        self.df_app_entitlements = df_app_entitlements.copy()

        self._normalize_data()
        self._build_entitlement_master()
        self._build_user_entitlement_matrix()

    def _normalize_data(self) -> None:
        """Sanitizes strings and identifiers."""
        self.df_identities["user_id"] = self.df_identities["user_id"].astype(str).str.strip()
        self.df_ad_memberships["user_id"] = self.df_ad_memberships["user_id"].astype(str).str.strip()
        self.df_ad_memberships["group_name"] = self.df_ad_memberships["group_name"].astype(str).str.strip()

        self.df_app_entitlements["user_id"] = self.df_app_entitlements["user_id"].astype(str).str.strip()
        self.df_app_entitlements["entitlement_name"] = self.df_app_entitlements["entitlement_name"].astype(str).str.strip()

    def _build_entitlement_master(self) -> None:
        """Unifies AD groups and application permissions into a consolidated list."""
        ad_records = self.df_ad_memberships[["user_id", "group_name"]].rename(
            columns={"group_name": "entitlement_name"}
        )
        ad_records["source_system"] = "ActiveDirectory"

        app_records = self.df_app_entitlements[["user_id", "entitlement_name"]].copy()
        app_records["source_system"] = self.df_app_entitlements.get("target_application", "App")

        self.df_consolidated = pd.concat([ad_records, app_records], ignore_index=True).drop_duplicates()

    def _build_user_entitlement_matrix(self) -> None:
        """
        Creates a binary User x Entitlement matrix (1 if granted, 0 otherwise).
        Crucial for clustering and role mining algorithms.
        """
        crosstab = pd.crosstab(
            self.df_consolidated["user_id"],
            self.df_consolidated["entitlement_name"]
        )
        self.matrix = (crosstab > 0).astype(int)

    def get_user_entitlements(self, user_id: str) -> Set[str]:
        """Returns the set of all entitlements held by a user."""
        sub = self.df_consolidated[self.df_consolidated["user_id"] == user_id]
        return set(sub["entitlement_name"].unique())

    def get_department_members(self, department: str, active_only: bool = True) -> List[str]:
        """Returns list of user_ids belonging to a department."""
        cond = self.df_identities["department"] == department
        if active_only:
            cond = cond & (self.df_identities["status"] == "ACTIVE")
        return self.df_identities[cond]["user_id"].tolist()

    def get_identity_summary(self) -> Dict[str, int]:
        """High level counts for executive dashboards."""
        total_identities = len(self.df_identities)
        active_identities = len(self.df_identities[self.df_identities["status"] == "ACTIVE"])
        terminated_identities = len(self.df_identities[self.df_identities["status"] == "TERMINATED"])
        total_unique_entitlements = self.df_consolidated["entitlement_name"].nunique()
        total_assignments = len(self.df_consolidated)

        return {
            "total_identities": total_identities,
            "active_identities": active_identities,
            "terminated_identities": terminated_identities,
            "unique_entitlements": total_unique_entitlements,
            "total_assignments": total_assignments
        }
