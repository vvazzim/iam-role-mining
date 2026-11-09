"""
Data models for IAM / IGA Role Mining and Security Audit.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Set


@dataclass
class Identity:
    user_id: str
    email: str
    first_name: str
    last_name: str
    department: str
    job_title: str
    manager_id: str
    status: str  # ACTIVE, SUSPENDED, TERMINATED
    contract_type: str = "CDI"  # CDI, PRESTATAIRE, STAGIAIRE


@dataclass
class Entitlement:
    entitlement_id: str
    entitlement_name: str
    target_system: str  # ActiveDirectory, SAP, Salesforce, GitHub, HR_Portal
    category: str  # Group, Role, Permission
    is_privileged: bool = False
    description: str = ""


@dataclass
class CandidateRole:
    role_id: str
    role_name: str
    department: str
    entitlements: Set[str]
    member_user_ids: Set[str]
    support_count: int
    coverage_ratio: float  # Percentage of department members covered
    complexity_score: float  # Metric measuring reduction in individual assignments


@dataclass
class SoDRule:
    rule_id: str
    rule_name: str
    entitlement_a: str
    entitlement_b: str
    risk_level: str  # CRITICAL, HIGH, MEDIUM
    description: str


@dataclass
class AuditFinding:
    finding_id: str
    category: str  # SOD_VIOLATION, ORPHAN_ACCOUNT, DORMANT_PRIVILEGE, PRIVILEGE_CREEP
    user_id: str
    user_name: str
    department: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    details: str
    remediation: str
