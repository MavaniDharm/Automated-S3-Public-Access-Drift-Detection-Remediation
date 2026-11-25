# 🛡️ Automated S3 Public Access Drift Detection \& Remediation

A real-time **DevSecOps guardrail** built on AWS that detects when someone disables S3 Block Public Access, automatically re-enables it, and sends an incident alert — all without human intervention.

!\[AWS](https://img.shields.io/badge/AWS-CloudTrail%20%7C%20EventBridge%20%7C%20Lambda%20%7C%20SNS-orange)
!\[Python](https://img.shields.io/badge/Python-3.11%2B-blue)
!\[Status](https://img.shields.io/badge/status-tested%20%26%20working-brightgreen)

\---

## 📖 Overview

Cloud misconfiguration is one of the leading causes of real-world data breaches, and a publicly exposed S3 bucket is one of the most common examples. This project implements a **self-healing security guardrail** that continuously watches for exactly this kind of configuration drift and corrects it automatically.

When someone disables **S3 Block Public Access** on any bucket in the account, the system:

1. **Detects** the change in near real time via AWS CloudTrail + EventBridge.
2. **Remediates** automatically by re-enabling all four Block Public Access settings with an AWS Lambda function.
3. **Alerts** the security team by email via Amazon SNS (bucket name, actor, and remediation status).
4. **Logs** every execution to Amazon CloudWatch for auditing.

This is a practical, fully serverless implementation of the **detect → remediate → alert** pattern used in real cloud security operations (CSPM / guardrail automation).

\---

## 🏗️ Architecture

```
 User / Attacker
       |
       v
 S3 PutBucketPublicAccessBlock / DeleteBucketPublicAccessBlock
       |
       v
 AWS CloudTrail        (DevSecOpsAuditTrail — logs the API call)
       |
       v
 Amazon EventBridge     (DetectS3PublicAccessChange rule)
       |
       v
 AWS Lambda             (RemediateS3PublicAccess)
       |                          \\
       v                           v
 S3 PutBucketPublicAccessBlock    Amazon SNS (DevSecOpsIncidentAlerts)
 (re-enable Block Public Access)         |
                                          v
                                   📧 Email Alert to Security Team
```

|Service|Role|
|-|-|
|**AWS CloudTrail**|Records every management API call, including S3 permission changes|
|**Amazon EventBridge**|Watches CloudTrail for the specific S3 events and triggers Lambda|
|**AWS Lambda**|Re-applies Block Public Access and publishes the alert|
|**Amazon SNS**|Delivers the email incident notification|
|**Amazon CloudWatch**|Captures Lambda execution logs for auditing|

> ⚠️ \*\*All resources must be created in the same AWS Region.\*\* If CloudTrail, EventBridge, Lambda and SNS are split across regions, EventBridge will not see the CloudTrail event and the Lambda will never trigger.

\---

## ✅ Prerequisites

* An AWS account (a student/sandbox account is sufficient) with console access
* IAM permissions for CloudTrail, S3, SNS, Lambda, EventBridge, IAM and CloudWatch
* A valid email address to receive SNS alerts
* Basic familiarity with Python 3 and JSON

\---

## 🚀 Setup Guide

### Step 1 — Enable CloudTrail Management Event Logging

1. Open the **AWS CloudTrail** console → **Create trail**
2. Name: `DevSecOpsAuditTrail`
3. Storage: create a **new S3 bucket** for the logs
4. Event type: **Management events**
5. API activity: select both **Read** and **Write**
6. Click **Create trail**

|||
|-|-|
|!\[CloudTrail trail created](screenshots/02-cloudtrail-trails-list-multiregion.png)|!\[CloudTrail logging](screenshots/01-cloudtrail-dashboard-trail-created.png)|
|*Trail created and visible in the Trails list*|*Dashboard confirming the trail is actively Logging*|

### Step 2 — Create an SNS Topic for Security Alerts

1. Open **Amazon SNS** → **Topics** → **Create topic**
2. Type: **Standard**, Name: `DevSecOpsIncidentAlerts`
3. Open the topic → **Create subscription** → Protocol: **Email** → enter your email
4. Confirm the subscription from your inbox

!\[SNS topic created](screenshots/03-sns-topic-created.png)
*SNS Standard topic `DevSecOpsIncidentAlerts` ready to publish alerts*

### Step 3 — Create the Auto-Remediation Lambda Function

1. **AWS Lambda** → **Create function** → Author from scratch
2. Name: `RemediateS3PublicAccess`, Runtime: **Python 3.11+**

!\[Lambda function created](screenshots/04-lambda-function-created.png)
*Lambda function created successfully*

#### IAM inline policy (attach to the Lambda execution role)

```json
{
  "Version": "2012-10-17",
  "Statement": \[
    {
      "Sid": "S3BlockPublicAccess",
      "Effect": "Allow",
      "Action": \[
        "s3:PutBucketPublicAccessBlock",
        "s3:GetBucketPublicAccessBlock"
      ],
      "Resource": "arn:aws:s3:::\*"
    },
    {
      "Sid": "PublishAlert",
      "Effect": "Allow",
      "Action": "sns:Publish",
      "Resource": "<your DevSecOpsIncidentAlerts topic ARN>"
    }
  ]
}
```

#### Environment variable

|Key|Value|
|-|-|
|`SNS\_TOPIC\_ARN`|ARN of the `DevSecOpsIncidentAlerts` topic|

#### `lambda\_function.py`

```python
import os
import json
import boto3
from botocore.exceptions import ClientError

s3 = boto3.client("s3")
sns = boto3.client("sns")

SNS\_TOPIC\_ARN = os.environ\["SNS\_TOPIC\_ARN"]


def is\_fully\_blocked(bucket):
    """Return True only if all four Block Public Access flags are on."""
    try:
        cfg = s3.get\_public\_access\_block(Bucket=bucket)\["PublicAccessBlockConfiguration"]
        return all(\[
            cfg.get("BlockPublicAcls"),
            cfg.get("IgnorePublicAcls"),
            cfg.get("BlockPublicPolicy"),
            cfg.get("RestrictPublicBuckets"),
        ])
    except ClientError as e:
        if e.response\["Error"]\["Code"] == "NoSuchPublicAccessBlockConfiguration":
            return False
        raise


def lambda\_handler(event, context):
    print("Event:", json.dumps(event))

    detail = event.get("detail", {})
    event\_name = detail.get("eventName", "Unknown")
    bucket = detail.get("requestParameters", {}).get("bucketName")

    identity = detail.get("userIdentity", {})
    actor = identity.get("arn") or identity.get("principalId") or "Unknown"

    if not bucket:
        print("No bucket name in event, exiting.")
        return {"status": "no-bucket"}

    # Avoid an infinite loop: ignore the change this Lambda makes itself
    if "RemediateS3PublicAccess" in actor:
        print("Change made by this Lambda, skipping.")
        return {"status": "skipped-self"}

    if is\_fully\_blocked(bucket):
        print(f"{bucket} is already fully blocked.")
        return {"status": "already-secure"}

    try:
        s3.put\_public\_access\_block(
            Bucket=bucket,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )
        status = "SUCCESS - Block Public Access re-enabled"
    except ClientError as e:
        status = f"FAILED - {e}"

    message = (
        "S3 PUBLIC ACCESS DRIFT DETECTED\\n\\n"
        f"Bucket      : {bucket}\\n"
        f"Event       : {event\_name}\\n"
        f"Actor       : {actor}\\n"
        f"Remediation : {status}\\n"
    )

    sns.publish(
        TopicArn=SNS\_TOPIC\_ARN,
        Subject=f"\[ALERT] S3 Public Access change on {bucket}",
        Message=message,
    )

    return {"status": status}
```

!\[Lambda code deployed](screenshots/05-lambda-code-source.png)
*Deployed Lambda code showing the SNS publish logic*

> 💡 \*\*Why the self-skip check matters:\*\* the Lambda itself calls `PutBucketPublicAccessBlock` to remediate, which would otherwise trigger the same EventBridge rule again and loop forever. The `actor` check breaks that loop.

### Step 4 — Create the EventBridge Rule

1. **Amazon EventBridge** → **Event buses** → `default` → **Rules** → **Create rule**
2. Name: `DetectS3PublicAccessChange`, Event bus: `default`
3. Rule type: **Rule with an event pattern**
4. Event source: **Other** → **Custom pattern (JSON editor)**

```json
{
  "source": \["aws.s3"],
  "detail-type": \["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": \["s3.amazonaws.com"],
    "eventName": \[
      "PutBucketPublicAccessBlock",
      "DeleteBucketPublicAccessBlock"
    ]
  }
}
```

5. Target: **AWS service → Lambda function → `RemediateS3PublicAccess`**
6. **Create rule**

!\[EventBridge rule created](screenshots/06-eventbridge-rule-created.png)
*Rule `DetectS3PublicAccessChange`, Enabled, targeting the Lambda function*

### Step 5 — Test and Verify

1. Create a test S3 bucket with Block Public Access **enabled**
2. Bucket → **Permissions** → **Block public access** → **Edit** → uncheck **Block all public access** → save → type `confirm`
3. Wait a minute or two for CloudTrail → EventBridge → Lambda to run
4. Refresh the bucket's Permissions page — Block Public Access should be **back On**
5. Check your inbox for the SNS alert email
6. Check **CloudWatch Logs** → `/aws/lambda/RemediateS3PublicAccess` for the execution trace

|||
|-|-|
|!\[Block Public Access disabled](screenshots/07-s3-block-public-access-disabled.png)|!\[Email alert received](screenshots/08-sns-email-alert-received.png)|
|*Drift triggered on the test bucket*|*Incident email received — Remediation: SUCCESS*|

**Result:** the drift was detected and reverted automatically within seconds, with a full audit trail in CloudWatch and an email alert naming the exact bucket, API event and IAM actor responsible.

### Step 6 — Clean Up

To avoid unnecessary AWS charges, delete the resources in this order:

1. Test S3 bucket (empty it first, then delete)
2. EventBridge rule — `DetectS3PublicAccessChange`
3. Lambda function — `RemediateS3PublicAccess`
4. SNS subscription, then the SNS topic — `DevSecOpsIncidentAlerts`
5. CloudTrail trail — `DevSecOpsAuditTrail`
6. CloudTrail log S3 bucket (empty it first, then delete)

\---

## 🔧 Troubleshooting

|Issue|Fix|
|-|-|
|Lambda never triggers|Make sure CloudTrail, the EventBridge rule and the Lambda function are all in the **same AWS Region**|
|Access denied errors|Confirm the inline IAM policy includes both S3 PublicAccessBlock actions **and** `sns:Publish` on the correct topic ARN|
|No email received|Confirm the SNS subscription status is **Confirmed**; check spam folder|
|No events in CloudWatch Logs|Confirm CloudTrail is **Logging** and **Write** management events are enabled|
|Lambda seems to trigger twice|Expected — handled by the actor self-check in the code, which skips events caused by the remediation Lambda itself|

\---

## 📁 Repository Structure

```
.
├── README.md
├── lambda\_function.py          # Auto-remediation Lambda source
├── iam\_policy.json             # Inline IAM policy for the Lambda role
├── eventbridge\_pattern.json    # EventBridge custom event pattern
└── screenshots/                # Console screenshots referenced above
    ├── 01-cloudtrail-dashboard-trail-created.png
    ├── 02-cloudtrail-trails-list-multiregion.png
    ├── 03-sns-topic-created.png
    ├── 04-lambda-function-created.png
    ├── 05-lambda-code-source.png
    ├── 06-eventbridge-rule-created.png
    ├── 07-s3-block-public-access-disabled.png
    └── 08-sns-email-alert-received.png
```

\---

## 🧠 What This Demonstrates

* Event-driven, serverless security automation (no polling, no servers)
* Practical use of CloudTrail + EventBridge for real-time API monitoring
* Auto-remediation patterns used in CSPM / cloud guardrail tooling
* Safe automation design (loop-prevention logic in the Lambda)
* Incident notification workflows with Amazon SNS

This detect → remediate → alert pattern can be extended to other common misconfigurations, such as open security groups, unencrypted EBS volumes, or exposed IAM access keys.

\---

## 👤 Author

**Dharm Mavani**
[LinkedIn](https://www.linkedin.com/in/dharm-mavani-075525344)

\---

## 📜 License

This project is provided for educational purposes as part of a cybersecurity training program.

