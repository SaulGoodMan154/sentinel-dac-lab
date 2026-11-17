#!/usr/bin/env python3
"""
Sentinel Detection-as-Code (DaC) Local Validator
Validates YAML detection rules for Microsoft Sentinel against:
- YAML syntax and structure
- Required Sentinel Scheduled Analytics Rule fields
- Valid UUID format for rule ID
- ISO 8601 duration syntax for queryFrequency & queryPeriod
- MITRE ATT&CK tactics and technique ID format
- Entity mapping schemas
- Basic KQL query sanity checks
- Uniqueness of rule IDs and names
"""

import os
import re
import sys
import uuid
from pathlib import Path
import yaml

# Supported MITRE ATT&CK Tactics in Microsoft Sentinel
VALID_TACTICS = {
    "InitialAccess",
    "Execution",
    "Persistence",
    "PrivilegeEscalation",
    "DefenseEvasion",
    "CredentialAccess",
    "Discovery",
    "LateralMovement",
    "Collection",
    "CommandAndControl",
    "Exfiltration",
    "Impact"
}

VALID_SEVERITIES = {"Informational", "Low", "Medium", "High"}
VALID_STATUSES = {"Available", "Enabled", "Disabled"}
VALID_OPERATORS = {"GreaterThan", "LessThan", "Equal", "NotEqual"}
VALID_ENTITY_TYPES = {"Account", "Host", "IP", "Url", "FileHash", "Process", "MailMessage", "AzureResource"}

# ISO 8601 duration pattern (e.g., PT5M, PT1H, P1D, PT1H30M)
ISO8601_DURATION_PATTERN = re.compile(
    r"^P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$"
)

# MITRE ATT&CK Technique pattern (e.g., T1110, T1110.001)
TECHNIQUE_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?$")

REQUIRED_FIELDS = [
    "id",
    "name",
    "description",
    "kind",
    "version",
    "severity",
    "status",
    "queryFrequency",
    "queryPeriod",
    "triggerOperator",
    "triggerThreshold",
    "tactics",
    "query"
]


def validate_iso_duration(val: str) -> bool:
    if not isinstance(val, str) or not val.startswith("P"):
        return False
    match = ISO8601_DURATION_PATTERN.match(val)
    if not match:
        return False
    # Ensure at least one duration component is non-empty
    return any(match.groups())


def validate_kql(query: str) -> list[str]:
    """Performs lightweight static checks on KQL query text."""
    errors = []
    if not query or not query.strip():
        errors.append("KQL query is empty.")
        return errors

    query_str = query.strip()

    # Check for basic unbalanced elements
    if query_str.count("(") != query_str.count(")"):
        errors.append("Unbalanced parentheses '(' and ')' in KQL query.")
    if query_str.count("[") != query_str.count("]"):
        errors.append("Unbalanced square brackets '[' and ']' in KQL query.")

    # Check that it doesn't end with a pipe
    if query_str.rstrip().endswith("|"):
        errors.append("KQL query ends with a dangling pipe character '|'.")

    # Check for non-existent KQL operators in Azure Monitor Log Analytics
    for bad_op in ["startswith_any", "endswith_any"]:
        if bad_op in query_str:
            errors.append(f"Invalid KQL operator '{bad_op}' found. Use standard 'or' conditions instead.")

    return errors


def validate_rule(file_path: Path, seen_ids: set, seen_names: set) -> tuple[list[str], list[str]]:
    """Validates a single detection YAML file. Returns (errors, warnings)."""
    errors = []
    warnings = []

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except Exception as e:
        errors.append(f"YAML parse error: {e}")
        return errors, warnings

    if not isinstance(data, dict):
        errors.append("Root element must be a YAML mapping/dictionary.")
        return errors, warnings

    # 1. Required fields check
    for field in REQUIRED_FIELDS:
        if field not in data or data[field] is None:
            errors.append(f"Missing required field: '{field}'")

    # If basic fields are missing, return early to avoid cascade errors
    if errors:
        return errors, warnings

    # 2. ID validation (Must be valid UUID)
    rule_id = str(data.get("id", "")).strip()
    try:
        val_uuid = uuid.UUID(rule_id, version=4)
        if str(val_uuid).lower() != rule_id.lower():
            errors.append(f"Rule ID '{rule_id}' is not a canonical UUIDv4 string.")
    except ValueError:
        errors.append(f"Rule ID '{rule_id}' is not a valid UUIDv4.")

    if rule_id.lower() in seen_ids:
        errors.append(f"Duplicate rule ID found: '{rule_id}'")
    else:
        seen_ids.add(rule_id.lower())

    # 3. Rule Name uniqueness and length
    rule_name = str(data.get("name", "")).strip()
    if len(rule_name) < 5:
        errors.append(f"Rule name '{rule_name}' is too short (min 5 chars).")
    if rule_name in seen_names:
        errors.append(f"Duplicate rule name found: '{rule_name}'")
    else:
        seen_names.add(rule_name)

    # 4. Severity validation
    severity = data.get("severity")
    if severity not in VALID_SEVERITIES:
        errors.append(f"Invalid severity '{severity}'. Must be one of {sorted(VALID_SEVERITIES)}.")

    # 5. Kind & Version validation
    kind = data.get("kind")
    if kind != "Scheduled":
        errors.append(f"Invalid kind '{kind}'. Expected 'Scheduled'.")

    version = data.get("version")
    if not isinstance(version, str) or not version.strip():
        errors.append("Field 'version' must be a valid version string (e.g., '1.0.0').")

    # 6. Status validation
    status = data.get("status")
    if status not in VALID_STATUSES:
        errors.append(f"Invalid status '{status}'. Must be one of {sorted(VALID_STATUSES)}.")

    # 7. Frequency and Period ISO 8601 validation
    freq = data.get("queryFrequency")
    if not validate_iso_duration(freq):
        errors.append(f"Invalid ISO 8601 duration for queryFrequency: '{freq}'. Example: 'PT5M' or 'PT1H'.")

    period = data.get("queryPeriod")
    if not validate_iso_duration(period):
        errors.append(f"Invalid ISO 8601 duration for queryPeriod: '{period}'. Example: 'PT15M' or 'P1D'.")

    # Ingestion lag buffer check (X8)
    if freq == period:
        warnings.append("queryFrequency equals queryPeriod; lookback overlap recommended to mitigate ingestion latency.")

    # 8. Operator & Threshold
    op = data.get("triggerOperator")
    if op not in VALID_OPERATORS:
        errors.append(f"Invalid triggerOperator '{op}'. Must be one of {sorted(VALID_OPERATORS)}.")

    thresh = data.get("triggerThreshold")
    if not isinstance(thresh, int) or thresh < 0:
        errors.append(f"Invalid triggerThreshold '{thresh}'. Must be a non-negative integer.")

    # 9. MITRE ATT&CK Tactics
    tactics = data.get("tactics", [])
    if not isinstance(tactics, list) or len(tactics) == 0:
        errors.append("'tactics' must be a non-empty list of ATT&CK tactics.")
    else:
        for tac in tactics:
            if tac not in VALID_TACTICS:
                errors.append(f"Invalid MITRE tactic '{tac}'. Must be one of {sorted(VALID_TACTICS)}.")

    # 10. MITRE ATT&CK Techniques
    techniques = data.get("relevantTechniques", [])
    if not isinstance(techniques, list):
        errors.append("'relevantTechniques' must be a list of ATT&CK technique IDs.")
    else:
        for tech in techniques:
            if not isinstance(tech, str) or not TECHNIQUE_PATTERN.match(tech):
                errors.append(f"Invalid MITRE technique ID format: '{tech}'. Expected pattern: 'T1xxx' or 'T1xxx.xxx'.")
        # Check for redundant parent techniques when sub-technique is present (X10)
        parents = {t.split(".")[0] for t in techniques if "." in t}
        for t in techniques:
            if "." not in t and t in parents:
                errors.append(f"Redundant parent technique '{t}' listed alongside its sub-technique.")

    # 11. KQL Query Validation & Anti-Patterns
    query_str = data.get("query", "")
    kql_errors = validate_kql(query_str)
    errors.extend(kql_errors)

    if re.search(r"Data\[\d+\]", query_str):
        warnings.append("Positional XML indexing Data[i] detected in query; prefer named extraction with regex.")
    if re.search(r"coalesce\(\s*IpAddress", query_str):
        warnings.append("coalesce on IpAddress detected; Windows Event 4625 logs '-' string, not null.")

    # 11. Entity Mappings Validation (if present)
    entity_mappings = data.get("entityMappings")
    if entity_mappings is not None:
        if not isinstance(entity_mappings, list):
            errors.append("'entityMappings' must be a list if defined.")
        else:
            for em in entity_mappings:
                if not isinstance(em, dict):
                    errors.append("Each item in 'entityMappings' must be a dictionary.")
                    continue
                etype = em.get("entityType")
                if etype not in VALID_ENTITY_TYPES:
                    errors.append(f"Invalid entityType '{etype}'. Must be one of {sorted(VALID_ENTITY_TYPES)}.")
                fmappings = em.get("fieldMappings")
                if not isinstance(fmappings, list) or len(fmappings) == 0:
                    errors.append(f"Entity '{etype}' must contain a non-empty 'fieldMappings' list.")

    # 12. Custom Details Validation
    custom_details = data.get("customDetails")
    if custom_details is not None:
        if not isinstance(custom_details, dict):
            errors.append("'customDetails' must be a dictionary if defined.")
        else:
            for k, v in custom_details.items():
                if len(k) > 20:
                    errors.append(f"CustomDetails key '{k}' exceeds Sentinel limit of 20 chars ({len(k)} chars).")
                if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", str(v)):
                    errors.append(f"CustomDetails value for '{k}' ('{v}') must be a simple alphanumeric column name.")

    # 13. Best Practice Warnings
    if "falsePositives" not in data:
        warnings.append("Best practice: include a 'falsePositives' field explaining known benign triggers.")

    return errors, warnings


def main():
    root_dir = Path(__file__).resolve().parent.parent
    detections_dir = root_dir / "detections"

    if not detections_dir.exists():
        print(f"[ERROR] Detections directory not found: {detections_dir}")
        sys.exit(1)

    yaml_files = sorted(list(detections_dir.glob("*.yaml")) + list(detections_dir.glob("*.yml")))

    if not yaml_files:
        print(f"[WARNING] No YAML detection files found in {detections_dir}")
        sys.exit(0)

    print("=" * 70)
    print(" Sentinel Detection-as-Code Local Validator")
    print(f" Scanning: {detections_dir}")
    print(f" Total rules found: {len(yaml_files)}")
    print("=" * 70)

    seen_ids = set()
    seen_names = set()
    total_errors = 0
    total_warnings = 0

    for file_path in yaml_files:
        errors, warnings = validate_rule(file_path, seen_ids, seen_names)
        status_icon = "PASS" if not errors else "FAIL"

        print(f"[{status_icon}] {file_path.name}")

        if errors:
            total_errors += len(errors)
            for err in errors:
                print(f"      ERROR: {err}")

        if warnings:
            total_warnings += len(warnings)
            for warn in warnings:
                print(f"      WARN:  {warn}")

    print("-" * 70)
    print(f"Validation complete: {len(yaml_files)} scanned | {total_errors} errors | {total_warnings} warnings")
    print("=" * 70)

    if total_errors > 0:
        print(f"[RESULT] FAILED: {total_errors} errors detected across rules.")
        sys.exit(1)
    else:
        print("[RESULT] SUCCESS: All detection rules passed validation!")
        sys.exit(0)


if __name__ == "__main__":
    main()

