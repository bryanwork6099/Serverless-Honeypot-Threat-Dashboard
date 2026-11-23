Technical Explanation
1. Project Overview
The AWS Serverless Honeypot & Threat Detection Dashboard is a controlled
decoy-request monitoring solution. It exposes selected HTTP endpoints
through Amazon API Gateway, inspects incoming requests with AWS Lambda,
records suspicious activity in Amazon DynamoDB, and uses Amazon
CloudWatch and Amazon SNS for monitoring and notification.

The solution is designed to identify suspicious indicators. It does not
execute submitted payloads or attempt to exploit systems.
2. Architecture Components
Amazon API Gateway
An HTTP API named HoneypotSecurityAPI receives requests through
selected routes, including:
- ANY /
- ANY /admin
- ANY /login
- ANY /wp-login.php
- ANY /.env
- ANY /.git
- ANY /phpmyadmin
- ANY /api/{proxy+}
The API invokes the HoneypotThreatDetector Lambda function. Because
individual routes are configured rather than a $default route,
requests to paths that do not match a configured route may receive an
API Gateway 404 response without reaching Lambda.
AWS Lambda
The Python Lambda function HoneypotThreatDetector inspects the HTTP
API request details, including the request path, query string, HTTP
method, source IP address, and user-agent.

The function URL-decodes the path and query string before applying its
detection rules. It classifies matching indicators into severity levels
and categories, tracks suspicious activity by source IP, and writes a
security event to DynamoDB.

The Lambda environment variables used by the implementation are:

  Variable              Value
  TABLE_NAME          HoneypotSecurityEvents
IP_ACTIVITY_TABLE   HoneypotIPActivity
Threat classification
The configured detection examples are:
  Initial severity        Category                Example indicators
  CRITICAL                Sensitive File Probing  /.env,
/wp-config.php,
/etc/passwd

  HIGH                    SQL Injection           union.*select,
or\s+1=1

  HIGH                    Directory Traversal     ../

  HIGH                    Cross-Site Scripting    <script

  MEDIUM                  Reconnaissance          /admin,
/wp-login.php,
/phpmyadmin, /.git
LOW                     No matching indicator   Request does not match
a configured rule
The detector checks the decoded request path and query string. These
patterns are indicators only; a match does not establish that an attack
succeeded.
Repeated suspicious activity and severity escalation
The implementation tracks suspicious requests by source IP in fixed
five-minute windows. The activity record includes the source IP, window
start time, suspicious request count, and an expiration timestamp.

The demonstrated escalation logic is:
- LOW remains LOW.
- At 5 or more suspicious requests in the current window, a MEDIUM
  event can be escalated to HIGH.
- At 10 or more suspicious requests in the current window, a non-LOW
  event can be escalated to CRITICAL.
- An event's initial classification is retained separately as
  originalSeverity.
The counter is for suspicious requests, not all requests. Shared NAT
gateways, proxies, and other users behind the same public IP can affect
counts, so the thresholds are suitable for a demonstration and require
tuning before production use.
Amazon DynamoDB
Two tables are used.
HoneypotSecurityEvents
This table stores individual detected events. Its partition key is
eventId (String). Event attributes include:
- eventId
- timestamp
- sourceIp
- path
- method
- userAgent
- severity
- originalSeverity
- attackCategory
- suspiciousCount
- queryString
HoneypotIPActivity
This table stores per-source-IP activity for a five-minute window. Its
partition key is sourceIp (String), and its sort key is windowStart
(String). The expiresAt numeric attribute is configured as the
DynamoDB TTL attribute. TTL deletion is asynchronous; expired records
are not necessarily removed immediately.
Amazon CloudWatch Logs and Metric Filters
Lambda execution and security event messages are written to the log
group:

/aws/lambda/HoneypotThreatDetector

Three metric filters use the JSON severity field:
  Filter                      Filter pattern                  Metric
  HoneypotCriticalThreats   { $.severity = "CRITICAL" }   CriticalThreatCount

  HoneypotHighThreats       { $.severity = "HIGH" }       HighThreatCount
HoneypotMediumThreats     { $.severity = "MEDIUM" }     MediumThreatCount
The custom metric namespace is HoneypotSecurityMetrics.

Metric filters process new matching log events. They do not backfill
metrics from log events that existed before the filters were created.
Metric publication and visibility can take several minutes.
CloudWatch Alarms
Three alarms monitor the custom metrics using a five-minute period and
Sum statistic:
  Alarm                       Metric                                     Threshold
  Alarm-Honeypot-Critical   CriticalThreatCount     Greater than or equal to 1

  Alarm-Honeypot-High       HighThreatCount         Greater than or equal to 5
Alarm-Honeypot-Medium     MediumThreatCount      Greater than or equal to 10
The thresholds are demonstration settings, not recommended universal
production thresholds. CloudWatch alarms transition between states such
as OK, ALARM, and INSUFFICIENT_DATA based on their configured evaluation
settings.
Amazon SNS
The SNS Standard topic HoneypotSecurityAlerts receives alarm
notifications. An email subscription must be confirmed by its recipient.
Each CloudWatch alarm is configured to publish to this topic when it
enters the ALARM state.

SNS notifications are generally associated with alarm state transitions,
not every individual matching request while the alarm remains in ALARM.
CloudWatch Dashboard
The dashboard HoneypotSecurityDashboard contains:
1. Honeypot Alarm Status
2. Critical Threat Activity
3. High Threat Activity
4. Medium Threat Activity
The charts visualize custom metrics, while the alarm widget displays
current alarm states.
3. End-to-End Processing Flow
1. A client sends an HTTP request to a configured decoy API Gateway
   route.
2. API Gateway invokes HoneypotThreatDetector.
3. Lambda extracts request metadata and decodes the path and query
   string.
4. Lambda compares the decoded request data with configured detection
   patterns.
5. Lambda determines the initial severity and attack category.
6. For suspicious requests with a source IP, Lambda updates the
   five-minute activity counter and applies the configured escalation
   logic.
7. Lambda writes the security event to HoneypotSecurityEvents.
8. Lambda logs the security event to CloudWatch Logs.
9. CloudWatch metric filters match the severity field and publish
   custom metric datapoints.
10. CloudWatch alarms evaluate the metrics.
11. When an alarm transitions into ALARM, it publishes to
    HoneypotSecurityAlerts.
12. SNS sends an email notification to the confirmed subscriber.
13. The CloudWatch dashboard displays the metrics and alarm states.
4. IAM Permissions
The Lambda execution role requires basic permissions for writing
CloudWatch Logs and the DynamoDB permissions used by the implementation:
- dynamodb:PutItem on HoneypotSecurityEvents
- dynamodb:UpdateItem on HoneypotIPActivity
Keep resource ARNs scoped to the required tables. Do not place long-term
AWS access keys in Lambda code, environment variables, or the
repository.
5. Scope and Limitations
- Detection is based on configured patterns in request paths and query
  strings; request bodies are not comprehensively inspected.
- The implementation does not prove that a request was successful or
  that a target was compromised.
- The configured API Gateway routes do not automatically capture every
  possible URL path.
- IP-based counters can combine activity from multiple users sharing
  an address.
- URL decoding and pattern matching are not substitutes for a full web
  application firewall or managed threat detection service.
- CloudWatch metric filters only process new incoming log events.
- DynamoDB TTL cleanup is asynchronous.
- Alarm thresholds require adjustment to the expected traffic volume
  and false-positive tolerance.
6. Security Guidance
Use this project only in an account and environment you control. Keep
the decoy service isolated from production workloads, avoid returning
sensitive information, do not execute or store uploaded malicious
payloads unnecessarily, monitor API usage and AWS costs, and review IAM
permissions regularly.
