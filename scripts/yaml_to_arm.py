#!/usr/bin/env python3
"""
YAML to ARM Template Compiler for Microsoft Sentinel Scheduled Analytics Rules
Reads all detection definitions from detections/*.yaml and compiles them into
deploy/alertRules.arm.json ready for 1-click Azure deployment.
"""

import json
import sys
from pathlib import Path
import yaml


def convert_detections_to_arm(detections_dir: Path, output_file: Path, table_filter: list = None):
    if not detections_dir.exists():
        print(f"[ERROR] Detections directory not found: {detections_dir}")
        sys.exit(1)

    yaml_files = sorted(list(detections_dir.glob("*.yaml")) + list(detections_dir.glob("*.yml")))

    if not yaml_files:
        print(f"[WARNING] No YAML detection files found in {detections_dir}")
        sys.exit(0)

    arm_template = {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "parameters": {
            "workspace": {
                "type": "string",
                "metadata": {
                    "description": "Name of the target Log Analytics Workspace hosting Microsoft Sentinel."
                }
            }
        },
        "resources": []
    }

    target_desc = f"all {len(yaml_files)}" if not table_filter else f"subset matching {table_filter}"
    print(f"Compiling {target_desc} detections into {output_file.name}...")

    for file_path in yaml_files:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except Exception as e:
            print(f"[ERROR] Failed to load {file_path.name}: {e}")
            sys.exit(1)

        # Filter by table if specified
        if table_filter:
            connectors = data.get("requiredDataConnectors", [])
            data_types = []
            for c in connectors:
                data_types.extend(c.get("dataTypes", []))
            if not any(dt in table_filter for dt in data_types):
                continue

        rule_id = str(data["id"]).strip()
        display_name = data.get("name")
        description = data.get("description", "")
        severity = data.get("severity", "Medium")
        enabled = data.get("status", "Available") in ["Available", "Enabled"]
        query = data.get("query", "").strip()
        query_freq = data.get("queryFrequency", "PT5M")
        query_period = data.get("queryPeriod", "PT5M")
        trigger_op = data.get("triggerOperator", "GreaterThan")
        trigger_thresh = data.get("triggerThreshold", 0)
        tactics = data.get("tactics", [])
        techniques = data.get("relevantTechniques", [])
        # Microsoft Sentinel ARM schema requires parent techniques only in 'T####' format
        arm_techniques = sorted(list(set(
            t.split('.')[0] for t in techniques if t.startswith('T') and t[1:].split('.')[0].isdigit()
        )))
        entity_mappings = data.get("entityMappings", [])
        custom_details = data.get("customDetails", {})

        # Map to Microsoft Sentinel ARM Resource
        resource = {
            "type": "Microsoft.OperationalInsights/workspaces/providers/alertRules",
            "apiVersion": "2022-11-01-preview",
            "name": f"[concat(parameters('workspace'), '/Microsoft.SecurityInsights/{rule_id}')]",
            "kind": "Scheduled",
            "properties": {
                "displayName": display_name,
                "description": description,
                "severity": severity,
                "enabled": enabled,
                "query": query,
                "queryFrequency": query_freq,
                "queryPeriod": query_period,
                "triggerOperator": trigger_op,
                "triggerThreshold": trigger_thresh,
                "tactics": tactics,
                "techniques": arm_techniques,
                "incidentConfiguration": {
                    "createIncident": True,
                    "groupingConfiguration": {
                        "enabled": False,
                        "reopenClosedIncident": False,
                        "lookbackDuration": "PT5H",
                        "matchingMethod": "AllEntities",
                        "groupByEntities": [],
                        "groupByAlertDetails": [],
                        "groupByCustomDetails": []
                    }
                },
                "suppressionDuration": "PT1H",
                "suppressionEnabled": False,
                "eventGroupingSettings": {
                    "aggregationKind": "SingleAlert"
                }
            }
        }

        if entity_mappings:
            resource["properties"]["entityMappings"] = entity_mappings
        if custom_details:
            resource["properties"]["customDetails"] = custom_details

        arm_template["resources"].append(resource)
        print(f"  + Added: {display_name} ({rule_id})")

    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as out:
        json.dump(arm_template, out, indent=2)

    print("-" * 70)
    print(f"[SUCCESS] ARM template successfully written to: {output_file}")
    print(f"Total alert rules generated: {len(arm_template['resources'])}")
    print("=" * 70)


def main():
    root_dir = Path(__file__).resolve().parent.parent
    detections_dir = root_dir / "detections"
    deploy_dir = root_dir / "deploy"

    # 1. Master template: All 15 detection rules
    convert_detections_to_arm(detections_dir, deploy_dir / "alertRules.arm.json")

    # 2. Modular subsets for phased enterprise deployment
    # Windows Security Events & Defender (Tables: SecurityEvent, SecurityAlert)
    convert_detections_to_arm(
        detections_dir,
        deploy_dir / "alertRules-endpoint.arm.json",
        table_filter=["SecurityEvent", "SecurityAlert"]
    )

    # Cloud & Identity (Tables: AzureActivity, SigninLogs, AuditLogs)
    convert_detections_to_arm(
        detections_dir,
        deploy_dir / "alertRules-cloud.arm.json",
        table_filter=["AzureActivity", "SigninLogs", "AuditLogs"]
    )

    # Sysmon Host Activity (Table: Event)
    convert_detections_to_arm(
        detections_dir,
        deploy_dir / "alertRules-sysmon.arm.json",
        table_filter=["Event"]
    )


if __name__ == "__main__":
    main()

