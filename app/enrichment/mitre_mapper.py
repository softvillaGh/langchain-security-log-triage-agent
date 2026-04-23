MITRE_MAPPINGS = {
    "Authentication Attack": {
        "tactic": "Credential Access",
        "technique_id": "T1110",
        "technique": "Brute Force"
    },
    "Brute Force / Repeated Malicious Activity": {
        "tactic": "Credential Access",
        "technique_id": "T1110",
        "technique": "Brute Force"
    },
    "Suspicious Web Access": {
        "tactic": "Initial Access",
        "technique_id": "T1190",
        "technique": "Exploit Public-Facing Application"
    },
    "Privilege Abuse": {
        "tactic": "Privilege Escalation",
        "technique_id": "T1068",
        "technique": "Exploitation for Privilege Escalation"
    },
    "Informational": {
        "tactic": "None",
        "technique_id": "N/A",
        "technique": "N/A"
    }
}


def enrich_with_mitre(results):
    enriched = []

    for result in results:
        attack_type = result.get("attack_type", "Informational")
        mitre = MITRE_MAPPINGS.get(
            attack_type,
            {"tactic": "Unknown", "technique_id": "Unknown", "technique": "Unknown"}
        )

        updated = result.copy()
        updated["mitre_tactic"] = mitre["tactic"]
        updated["mitre_technique_id"] = mitre["technique_id"]
        updated["mitre_technique"] = mitre["technique"]
        enriched.append(updated)

    return enriched
