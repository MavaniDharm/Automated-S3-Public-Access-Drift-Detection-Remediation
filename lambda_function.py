import os
import json
import boto3
from botocore.exceptions import ClientError

s3 = boto3.client("s3")
sns = boto3.client("sns")

SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]


def is_fully_blocked(bucket):
    """Return True only if all four Block Public Access flags are on."""
    try:
        cfg = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
        return all([
            cfg.get("BlockPublicAcls"),
            cfg.get("IgnorePublicAcls"),
            cfg.get("BlockPublicPolicy"),
            cfg.get("RestrictPublicBuckets"),
        ])
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
            return False
        raise


def lambda_handler(event, context):
    print("Event:", json.dumps(event))

    detail = event.get("detail", {})
    event_name = detail.get("eventName", "Unknown")
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

    if is_fully_blocked(bucket):
        print(f"{bucket} is already fully blocked.")
        return {"status": "already-secure"}

    try:
        s3.put_public_access_block(
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
        "S3 PUBLIC ACCESS DRIFT DETECTED\n\n"
        f"Bucket      : {bucket}\n"
        f"Event       : {event_name}\n"
        f"Actor       : {actor}\n"
        f"Remediation : {status}\n"
    )

    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=f"[ALERT] S3 Public Access change on {bucket}",
        Message=message,
    )

    return {"status": status}
