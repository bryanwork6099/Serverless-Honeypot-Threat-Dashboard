import json
import boto3
import os
import uuid
import re

from datetime import datetime, timezone
from urllib.parse import unquote_plus

dynamodb = boto3.resource('dynamodb')

event_table = dynamodb.Table(
    os.environ['TABLE_NAME']
)

ip_table = dynamodb.Table(
    os.environ['IP_ACTIVITY_TABLE']
)

# Five-minute tracking window
WINDOW_SECONDS = 300

# Suspicious request detection rules
THREAT_RULES = [
    {
        "severity": "CRITICAL",
        "category": "Sensitive File Probing",
        "patterns": [
            r"/\.env",
            r"/wp-config\.php",
            r"/etc/passwd"
        ]
    },
    {
        "severity": "HIGH",
        "category": "SQL Injection",
        "patterns": [
            r"union.*select",
            r"or\s+1=1"
        ]
    },
    {
        "severity": "HIGH",
        "category": "Directory Traversal",
        "patterns": [
            r"\.\./"
        ]
    },
    {
        "severity": "HIGH",
        "category": "Cross-Site Scripting",
        "patterns": [
            r"<script"
        ]
    },
    {
        "severity": "MEDIUM",
        "category": "Reconnaissance",
        "patterns": [
            r"/admin",
            r"/wp-login\.php",
            r"/phpmyadmin",
            r"/\.git"
        ]
    }
]

SEVERITY_LEVELS = [
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL"
]


def classify_threat(path, query_string):

    request = (
        path + " " + query_string
    ).lower()

    for rule in THREAT_RULES:

        for pattern in rule["patterns"]:

            if re.search(pattern, request):

                return (
                    rule["severity"],
                    rule["category"]
                )

    return "LOW", "Normal Traffic"


def track_ip_activity(source_ip):

    now = int(datetime.now(
        timezone.utc
    ).timestamp())

    window_epoch = (
        now // WINDOW_SECONDS
    ) * WINDOW_SECONDS

    window_start = datetime.fromtimestamp(
        window_epoch,
        timezone.utc
    ).isoformat()

    expires_at = window_epoch + 86400

    response = ip_table.update_item(
        Key={
            "sourceIp": source_ip,
            "windowStart": window_start
        },
        UpdateExpression=(
            "SET expiresAt = if_not_exists(expiresAt, :ttl) "
            "ADD suspiciousCount :increment"
        ),
        ExpressionAttributeValues={
            ":ttl": expires_at,
            ":increment": 1
        },
        ReturnValues="UPDATED_NEW"
    )

    return int(
        response["Attributes"]["suspiciousCount"]
    )


def escalate_severity(severity, count):

    if severity == "LOW":
        return severity

    if count >= 10:
        return "CRITICAL"

    if count >= 5:
        if SEVERITY_LEVELS.index(severity) < 2:
            return "HIGH"

    return severity


def lambda_handler(event, context):

    print(
        "Received request:",
        json.dumps(event)
    )

    try:

        http = event.get(
            "requestContext", {}
        ).get("http", {})

        path = unquote_plus(
            event.get("rawPath", "/")
        )

        method = http.get(
            "method", "UNKNOWN"
        )

        source_ip = http.get(
            "sourceIp", "UNKNOWN"
        )

        query_string = unquote_plus(
            event.get("rawQueryString", "")
        )

        user_agent = event.get(
            "headers", {}
        ).get("user-agent", "UNKNOWN")

        # Initial threat classification
        severity, category = classify_threat(
            path,
            query_string
        )

        # Track suspicious requests per IP
        suspicious_count = 0

        if (
            severity != "LOW"
            and source_ip != "UNKNOWN"
        ):

            suspicious_count = track_ip_activity(
                source_ip
            )

        # Escalate repeated suspicious activity
        final_severity = escalate_severity(
            severity,
            suspicious_count
        )

        security_event = {
            "eventId": str(uuid.uuid4()),
            "timestamp": datetime.now(
                timezone.utc
            ).isoformat(),
            "sourceIp": source_ip,
            "path": path,
            "method": method,
            "userAgent": user_agent,
            "severity": final_severity,
            "originalSeverity": severity,
            "attackCategory": category,
            "suspiciousCount": suspicious_count,
            "queryString": query_string
        }

        # Store security event
        event_table.put_item(
            Item=security_event
        )

        print(
            "Security event:",
            json.dumps(security_event)
        )

        return {
            "statusCode": 200,
            "headers": {
                "Content-Type": "application/json"
            },
            "body": json.dumps({
                "message": "Request processed",
                "eventId": security_event["eventId"],
                "severity": final_severity,
                "category": category,
                "suspiciousCount": suspicious_count
            })
        }

    except Exception as e:

        print("ERROR:", str(e))

        return {
            "statusCode": 500,
            "body": json.dumps({
                "error": "Internal server error"
            })
        }
