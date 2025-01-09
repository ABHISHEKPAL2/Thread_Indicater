import json

# Input JSON
input_data = {
    "rule_id": "<rule_id>",
    "status": "active",
    "tenant_id": "ABC1234",
    "job": {
<<<<<<< HEAD
        "query": "source = seceon-azure-ad-sec8149 | where activityDisplayName = \"Delete conditional access policy\" | eval ipAddress = initiatedBy.user.ipAddress, userId = initiatedBy.user.id, entity = initiatedBy.user.userPrincipalName, entity_type = \"user\"",
=======
        "query": "source = seceon-azure-ad-sec8149 | where activityDisplayName = \"Reset password (by admin)\" or activityDisplayName = \"Change password (self-service)\" | eval ipAddress = initiatedBy.user.ipAddress, userid = initiatedBy.user.id, userPrincipalName = initiatedBy.user.userPrincipalName | fields activityDateTime, ipAddress, userid, userPrincipalName, activityDisplayName",
>>>>>>> 1774978531b26a7fe82acaf77e498da59f2367c4
        "query_type": "PPL",
        "job_type": "detection",
        "logsource": {
            "category": "Cloud",
            "product": "Azure",
            "service": "Audit"
        }
    },
    "threat_indicators_fields": {
        "event_type_id": "<rule_id>",
<<<<<<< HEAD
        "event_type_name": "Conditional Access Policy Deletion",
        "event_category": "Conditional Access",
        "severity": "critical",
        "event_origin": "cloud",
        "source_data_type": "Azure Activity Logs",
        "message": "A conditional access policy was deleted by user: {{entity:-}}, indicating potential unauthorized changes or malicious activity."
    },
    "description": "This rule monitors for deletions of conditional access policies, which may indicate unauthorized changes or malicious activity. Immediate review and validation of such actions are recommended to maintain compliance and security.",
=======
        "event_type_name": "Password Change or Reset",
        "event_category": "Identity & Access Management",
        "severity": "medium",
        "event_origin": "cloud",
        "source_data_type": "Azure Activity Logs",
        "message": "A password change or reset event has occurred, which could be legitimate or indicate unauthorized access."
    },
    "description": "This rule detects when a password change or reset occurs for a user account. It can be a legitimate change but may also indicate unauthorized activity if not initiated by the user.",
>>>>>>> 1774978531b26a7fe82acaf77e498da59f2367c4
    "schedule": {
        "type": "recurring",
        "interval": "*/15 * * * *"
    }
}

<<<<<<< HEAD

=======
>>>>>>> 1774978531b26a7fe82acaf77e498da59f2367c4
# Extract event_type_name and create dynamic filename
event_type_name = input_data["threat_indicators_fields"]["event_type_name"]
file_name = f"{event_type_name.replace(' ', '_')}.json"

# Save to file
with open(file_name, "w") as json_file:
    json.dump(input_data, json_file, indent=4)

print(f"JSON data has been saved to {file_name}")
