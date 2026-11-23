# Deployment Guide

## 1. Overview

This guide describes how to deploy the AWS Serverless Honeypot & Threat
Detection Dashboard manually through the AWS Management Console.

The implementation uses the Singapore AWS Region:

`ap-southeast-1`

Resource names used in this project:

  Resource                      Name
  ----------------------------- -----------------------------
  API Gateway HTTP API          `HoneypotSecurityAPI`
  Lambda function               `HoneypotThreatDetector`
  DynamoDB event table          `HoneypotSecurityEvents`
  DynamoDB IP activity table    `HoneypotIPActivity`
  CloudWatch metric namespace   `HoneypotSecurityMetrics`
  SNS topic                     `HoneypotSecurityAlerts`
  CloudWatch dashboard          `HoneypotSecurityDashboard`

Console labels may change over time. Confirm the selected AWS Region
before creating resources.

## 2. Create the Security Event Table

1.  Open the AWS Management Console and navigate to DynamoDB.
2.  Select **Tables** and choose **Create table**.
3.  Enter table name `HoneypotSecurityEvents`.
4.  Set the partition key to `eventId` with type **String**.
5.  Do not add a sort key.
6.  Select on-demand capacity for the demonstration.
7.  Create the table.

The Lambda function uses this table to store individual security events.

## 3. Create the IP Activity Table

1.  In DynamoDB, choose **Create table**.
2.  Enter table name `HoneypotIPActivity`.
3.  Set partition key `sourceIp` with type **String**.
4.  Add sort key `windowStart` with type **String**.
5.  Use on-demand capacity.
6.  Create the table.

### Enable TTL

1.  Open `HoneypotIPActivity`.
2.  Find the **Additional settings** or **Time to Live (TTL)**
    configuration.
3.  Enable TTL.
4.  Set the TTL attribute name to `expiresAt`.
5.  Save the configuration.

The application must write `expiresAt` as a numeric Unix timestamp in
seconds. DynamoDB TTL cleanup is asynchronous.

## 4. Create the Lambda Execution Role

Create or configure an IAM role for the Lambda function.

The role needs:

-   Basic Lambda execution permissions for writing CloudWatch Logs.
-   `dynamodb:PutItem` on the `HoneypotSecurityEvents` table.
-   `dynamodb:UpdateItem` on the `HoneypotIPActivity` table.

Example inline policy (replace the account ID if deploying in another
account):

``` json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "dynamodb:PutItem"
      ],
      "Resource": "arn:aws:dynamodb:ap-southeast-1:366554472163:table/HoneypotSecurityEvents"
    },
    {
      "Effect": "Allow",
      "Action": [
        "dynamodb:UpdateItem"
      ],
      "Resource": "arn:aws:dynamodb:ap-southeast-1:366554472163:table/HoneypotIPActivity"
    }
  ]
}
```

Use your own account ID and region when adapting this policy. Keep
permissions restricted to the required actions and table resources.

## 5. Create the Lambda Function

1.  Open AWS Lambda.
2.  Choose **Create function**.
3.  Select **Author from scratch**.
4.  Set function name to `HoneypotThreatDetector`.
5.  Select Python 3.13 runtime, as used in this project.
6.  Select the appropriate architecture.
7.  Assign the execution role created in the previous step.
8.  Create the function.

Paste the completed Python threat detector code into the Lambda editor
and deploy it.

### Configure environment variables

Under **Configuration → Environment variables**, add:

  Key                   Value
  --------------------- --------------------------
  `TABLE_NAME`          `HoneypotSecurityEvents`
  `IP_ACTIVITY_TABLE`   `HoneypotIPActivity`

Ensure the code uses the same table names and environment variable
names.

### Test the Lambda function

Use a test event shaped like an API Gateway HTTP API payload. Confirm
that the function can parse the request, classify the indicator, write
to DynamoDB, and return a response.

## 6. Create the API Gateway HTTP API

1.  Open Amazon API Gateway.
2.  Choose **Create API**.
3.  Select **HTTP API**.
4.  Add an integration for the `HoneypotThreatDetector` Lambda function.
5.  Name the API `HoneypotSecurityAPI`.
6.  Configure the routes used by the project:

  Method   Route
  -------- -----------------
  ANY      `/`
  ANY      `/admin`
  ANY      `/login`
  ANY      `/wp-login.php`
  ANY      `/.env`
  ANY      `/.git`
  ANY      `/phpmyadmin`
  ANY      `/api/{proxy+}`

7.  Configure the `$default` stage with auto-deploy enabled, as used in
    this implementation.
8.  Create or deploy the API.
9.  Verify that API Gateway has permission to invoke the Lambda
    integration.
10. Copy the API invoke URL for testing.

The project API invoke URL used during the original implementation was:

`https://lrijckaanh.execute-api.ap-southeast-1.amazonaws.com`

Your API ID and invoke URL will differ if you create a new API.

**Route behavior:** The project uses individual routes rather than a
`$default` catch-all route. A request to a path that does not match a
configured route may return 404 before Lambda is invoked. The
`/api/{proxy+}` route only captures paths beneath `/api/`.

## 7. Test API Gateway and Lambda Integration

In PowerShell, set the invoke URL:

``` powershell
$API = "https://YOUR_API_ID.execute-api.ap-southeast-1.amazonaws.com"
```

Test the endpoints:

``` powershell
Invoke-RestMethod -Uri "$($API)/admin" -Method GET

Invoke-RestMethod -Uri "$($API)/login?username=admin%20OR%201=1" -Method GET

Invoke-RestMethod -Uri "$($API)/.env" -Method GET
```

Confirm that the responses include the expected severity and category,
and that records are written to DynamoDB.

## 8. Configure CloudWatch Metric Filters

1.  Open CloudWatch.
2.  Navigate to **Logs → Log groups**.
3.  Open `/aws/lambda/HoneypotThreatDetector`.
4.  Select **Metric filters**.
5.  Create the following filters.

### CRITICAL

Filter pattern:

``` text
{ $.severity = "CRITICAL" }
```

-   Filter name: `HoneypotCriticalThreats`
-   Namespace: `HoneypotSecurityMetrics`
-   Metric name: `CriticalThreatCount`
-   Metric value: `1`

### HIGH

Filter pattern:

``` text
{ $.severity = "HIGH" }
```

-   Filter name: `HoneypotHighThreats`
-   Namespace: `HoneypotSecurityMetrics`
-   Metric name: `HighThreatCount`
-   Metric value: `1`

### MEDIUM

Filter pattern:

``` text
{ $.severity = "MEDIUM" }
```

-   Filter name: `HoneypotMediumThreats`
-   Namespace: `HoneypotSecurityMetrics`
-   Metric name: `MediumThreatCount`
-   Metric value: `1`

Generate new matching requests after creating the filters. Metric
filters do not backfill historical log events. Allow time for custom
metrics to appear.

**Log format check:** These JSON filter patterns require the relevant
log event to be recognized as a JSON event with a top-level `severity`
field. Inspect the actual CloudWatch log event. If the JSON is embedded
after a text prefix rather than logged as a standalone JSON event,
adjust the logging format or filter pattern accordingly.

## 9. Create CloudWatch Alarms

Open **CloudWatch → Alarms → Create alarm** and select the relevant
custom metric under `HoneypotSecurityMetrics`.

Use the following configuration:

  --------------------------------------------------------------------------------------------
  Setting                           CRITICAL                    HIGH                    MEDIUM
  -------------- --------------------------- ----------------------- -------------------------
  Metric               `CriticalThreatCount`       `HighThreatCount`       `MediumThreatCount`

  Statistic                              Sum                     Sum                       Sum

  Period                           5 minutes               5 minutes                 5 minutes

  Comparison                   Greater/Equal           Greater/Equal             Greater/Equal

  Threshold                                1                       5                        10

  Alarm name       `Alarm-Honeypot-Critical`   `Alarm-Honeypot-High`   `Alarm-Honeypot-Medium`
  --------------------------------------------------------------------------------------------

These thresholds are demonstration settings. Tune them for expected
request volume and operational requirements.

## 10. Create the SNS Topic and Email Subscription

1.  Open Amazon SNS.
2.  Navigate to **Topics** and choose **Create topic**.
3.  Select **Standard**.
4.  Enter topic name `HoneypotSecurityAlerts`.
5.  Create the topic.
6.  Open the topic and choose **Create subscription**.
7.  Select protocol **Email**.
8.  Enter the recipient email address.
9.  Create the subscription.
10. Open the confirmation email and select **Confirm subscription**.
11. Return to SNS and verify that the subscription status is
    **Confirmed**.

## 11. Connect SNS to the CloudWatch Alarms

For each of the three alarms:

1.  Open the alarm in CloudWatch.
2.  Edit the alarm configuration.
3.  In the notification section, configure an action for the **In
    alarm** state.
4.  Select the existing SNS topic `HoneypotSecurityAlerts`.
5.  Save the alarm.

Repeat for:

-   `Alarm-Honeypot-Critical`
-   `Alarm-Honeypot-High`
-   `Alarm-Honeypot-Medium`

Verify the topic is selected and the notification action is enabled for
all three alarms.

## 12. Create the CloudWatch Dashboard

1.  Open **CloudWatch → Dashboards**.
2.  Choose **Create dashboard**.
3.  Enter `HoneypotSecurityDashboard`.
4.  Add an **Alarm status** widget and select all three honeypot alarms.
5.  Add a **Line** widget for `CriticalThreatCount`.
6.  Add a **Line** widget for `HighThreatCount`.
7.  Add a **Line** widget for `MediumThreatCount`.
8.  Name the widgets:
    -   `Honeypot Alarm Status`
    -   `Critical Threat Activity`
    -   `High Threat Activity`
    -   `Medium Threat Activity`
9.  Arrange the widgets and save the dashboard.

## 13. Final Deployment Verification

Use the companion `TESTING.md` checklist to validate:

-   API Gateway routes invoke Lambda.
-   Threat patterns are classified correctly.
-   Both DynamoDB tables receive the expected records.
-   IP activity counters update.
-   CloudWatch metric filters publish metrics.
-   All three alarms evaluate the metrics.
-   SNS email notifications are received for alarm state transitions.
-   Dashboard widgets display the metrics and alarm states.

## 14. Cost and Cleanup Considerations

This project uses managed AWS services that may incur charges, including
API Gateway, Lambda, DynamoDB, CloudWatch Logs and metrics, CloudWatch
alarms and dashboards, and SNS.

Review the AWS Billing console after testing. If the project is no
longer needed, remove resources carefully to avoid ongoing charges:

1.  Disable or delete the API Gateway API.
2.  Delete the Lambda function.
3.  Delete the CloudWatch alarms, dashboard, and metric filters.
4.  Delete the SNS subscription and topic.
5.  Delete the DynamoDB tables if their data is no longer required.
6.  Review and remove the dedicated IAM role and policies if no longer
    used.
7.  Review CloudWatch log retention and delete log groups if
    appropriate.

Only delete resources that belong to this project and that you no longer
need. Export any screenshots or records required for your portfolio
before cleanup.
