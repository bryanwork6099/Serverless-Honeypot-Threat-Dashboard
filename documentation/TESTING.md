# Testing and Validation Guide

## 1. Purpose

This document describes how to validate the AWS Serverless Honeypot &
Threat Detection Dashboard. Tests use controlled HTTP requests against
the project's own API Gateway endpoint.

The tests verify request handling, initial threat classification,
DynamoDB persistence, IP activity tracking, CloudWatch metrics, alarm
transitions, and SNS email notifications.

## 2. Prerequisites

Before testing, confirm that:

-   The API Gateway HTTP API is deployed.
-   `HoneypotThreatDetector` is integrated with the API.
-   The Lambda environment variables point to the correct DynamoDB
    tables.
-   The Lambda role has the required DynamoDB and CloudWatch Logs
    permissions.
-   Both DynamoDB tables exist.
-   The three CloudWatch metric filters and alarms exist.
-   The SNS email subscription is confirmed.
-   All three alarms have the `HoneypotSecurityAlerts` SNS action
    configured.

Set the API base URL in PowerShell:

``` powershell
$API = "https://lrijckaanh.execute-api.ap-southeast-1.amazonaws.com"
```

Use your deployed API endpoint if it differs.

## 3. Request Classification Tests

Run the following requests individually.

### Test 1 -- Reconnaissance (MEDIUM)

``` powershell
Invoke-RestMethod -Uri "$($API)/admin" -Method GET
```

Expected initial classification:

-   Severity: `MEDIUM`
-   Category: `Reconnaissance`

### Test 2 -- SQL Injection Indicator (HIGH)

``` powershell
Invoke-RestMethod -Uri "$($API)/login?username=admin%20OR%201=1" -Method GET
```

Expected initial classification:

-   Severity: `HIGH`
-   Category: `SQL Injection`

This test verifies that URL-encoded query-string content is decoded
before classification.

### Test 3 -- Sensitive File Probing (CRITICAL)

``` powershell
Invoke-RestMethod -Uri "$($API)/.env" -Method GET
```

Expected initial classification:

-   Severity: `CRITICAL`
-   Category: `Sensitive File Probing`

### Additional optional tests

XSS indicator:

``` powershell
Invoke-RestMethod -Uri "$($API)/login?search=%3Cscript%3Ealert(1)%3C/script%3E" -Method GET
```

Directory traversal indicator in a query parameter:

``` powershell
Invoke-RestMethod -Uri "$($API)/login?file=..%2F..%2Fetc%2Fpasswd" -Method GET
```

These tests should be performed only against the project's own decoy
endpoint.

## 4. Severity Escalation and IP Activity Tests

The implementation tracks suspicious requests by source IP in fixed
five-minute windows.

The demonstration escalation logic includes:

-   A MEDIUM event can escalate to HIGH at 5 or more suspicious
    requests.
-   A non-LOW event can escalate to CRITICAL at 10 or more suspicious
    requests.
-   LOW remains LOW.

To generate repeated MEDIUM requests:

``` powershell
1..5 | ForEach-Object {
    Invoke-RestMethod -Uri "$($API)/admin" -Method GET
}
```

Inspect each response and the corresponding DynamoDB records. The final
severity depends on the current source-IP counter and window; do not
assume a test begins with a counter of zero.

A new five-minute window starts as time advances. Shared public IP
addresses can cause multiple clients' suspicious requests to contribute
to the same counter.

## 5. DynamoDB Validation

### `HoneypotSecurityEvents`

Open DynamoDB, select `HoneypotSecurityEvents`, and explore table items.

Verify that recent events contain the expected attributes:

-   `eventId`
-   `timestamp`
-   `sourceIp`
-   `path`
-   `method`
-   `userAgent`
-   `severity`
-   `originalSeverity`
-   `attackCategory`
-   `suspiciousCount`
-   `queryString`

Use `originalSeverity` to validate the initial pattern classification.
The final `severity` may be higher because of escalation.

### `HoneypotIPActivity`

Open `HoneypotIPActivity` and inspect the item for the test source IP.

Verify:

-   `sourceIp`
-   `windowStart`
-   `suspiciousCount`
-   `expiresAt`

The `expiresAt` attribute should be a numeric Unix timestamp. TTL
deletion is asynchronous, so an expired item may remain visible
temporarily.

## 6. CloudWatch Logs and Metric Filter Validation

Open the log group:

`/aws/lambda/HoneypotThreatDetector`

Inspect recent log streams and confirm that security event logs contain
the JSON fields used by the metric filters, particularly `severity`.

The configured metric filters are:

  Severity   Metric name             Filter pattern
  ---------- ----------------------- -------------------------------
  CRITICAL   `CriticalThreatCount`   `{ $.severity = "CRITICAL" }`
  HIGH       `HighThreatCount`       `{ $.severity = "HIGH" }`
  MEDIUM     `MediumThreatCount`     `{ $.severity = "MEDIUM" }`

Namespace:

`HoneypotSecurityMetrics`

Metric filters process new log events after creation; historical log
entries are not automatically counted. Allow several minutes for metrics
to appear.

If metrics do not increase, inspect the raw log event and confirm that
the metric filter pattern matches the actual JSON structure. If the JSON
is embedded as text after a prefix, the filter may need to be adjusted
to match the real log format.

## 7. CloudWatch Alarm Validation

Confirm the configured alarms:

  -------------------------------------------------------------------------------------------------
  Alarm                       Metric                  Period        Statistic             Threshold
  --------------------------- ----------------------- ------------- ------------- -----------------
  `Alarm-Honeypot-Critical`   `CriticalThreatCount`   5 minutes     Sum                         ≥ 1

  `Alarm-Honeypot-High`       `HighThreatCount`       5 minutes     Sum                         ≥ 5

  `Alarm-Honeypot-Medium`     `MediumThreatCount`     5 minutes     Sum                        ≥ 10
  -------------------------------------------------------------------------------------------------

Generate matching requests and inspect the metric and alarm history.

Alarm evaluation is not instantaneous. Wait for CloudWatch to receive
and evaluate datapoints. A graph datapoint represents a value for a
metric period; it is not necessarily a lifetime total.

## 8. SNS Email Notification Validation

Confirm that:

-   The SNS topic is `HoneypotSecurityAlerts`.
-   The email subscription status is `Confirmed`.
-   Each alarm has an enabled notification action for the `In alarm`
    state.
-   Each alarm points to the correct SNS topic.

To test notifications, allow an alarm to transition from OK to ALARM
after its notification action is configured. Check the inbox and spam
folder.

CloudWatch generally sends alarm notifications on state transitions.
Updating an alarm action while it is already in ALARM does not
necessarily cause a new notification. To test again, allow the alarm to
return to OK and then trigger a new ALARM transition.

## 9. Dashboard Validation

Open `HoneypotSecurityDashboard` and confirm that it contains:

1.  `Honeypot Alarm Status`
2.  `Critical Threat Activity`
3.  `High Threat Activity`
4.  `Medium Threat Activity`

Verify that metric charts display datapoints after new matching requests
are processed and that the alarm widget reflects the current alarm
states.

## 10. Test Results Checklist

Use this checklist when documenting a test run:

-   [ ] API Gateway receives requests on configured routes.
-   [ ] MEDIUM reconnaissance indicator is classified correctly.
-   [ ] HIGH SQL injection indicator is classified correctly.
-   [ ] CRITICAL sensitive-file indicator is classified correctly.
-   [ ] URL-encoded query strings are decoded and inspected.
-   [ ] Security events are written to `HoneypotSecurityEvents`.
-   [ ] Suspicious IP activity is written to `HoneypotIPActivity`.
-   [ ] `suspiciousCount` increases in the applicable five-minute
    window.
-   [ ] CloudWatch metric filters publish the expected metrics.
-   [ ] CRITICAL alarm transitions as expected.
-   [ ] HIGH alarm transitions as expected.
-   [ ] MEDIUM alarm transitions as expected.
-   [ ] SNS email notification is received for each tested alarm
    transition.
-   [ ] Dashboard widgets display metrics and alarm states.

## 11. Interpretation and Safety Notes

A matching request indicates a suspicious pattern, not proof of a
successful attack. Record initial classification separately from
escalated severity. Run tests only against infrastructure you own or are
authorized to assess. Avoid sending destructive payloads or testing
against third-party systems.
