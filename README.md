# Intelligent-file-ingestion-system
# Intelligent Document Ingestion — Lambda Code + README + Design Document

> Canvas contents: Lambda handler (Python), README, and Design Document for portfolio use. Use this as a ready-to-present artifact for a senior AWS engineer role.

---

# Table of Contents

1. README — Quick start
2. Design Document

   * Business requirements
   * High-level architecture
   * Component details
   * Security & compliance
   * Observability & testing
   * Failure modes & mitigation
   * Cost considerations
3. Lambda: `s3_file_processor.py` (production-ready Python 3.11 handler)
4. Deployment options (SAM, CDK, Terraform) — sample snippets
5. Appendix: IAM policies, sample payloads, CLI test commands

---

# 1. README — Quick start

## Overview

This project implements an enterprise-grade *File Upload Notification System*. When new objects are uploaded to an S3 ingestion bucket, an S3 Event triggers a Lambda function. The Lambda validates and extracts metadata, publishes a notification to an SNS topic (for human/ops notification or integrations), and writes a metadata message to an SQS queue for downstream processing.

This artifact includes:

* `s3_file_processor.py` — Lambda handler (Python 3.11)
* Architecture and design rationale
* Deployment guidance (SAM / CDK / Terraform snippets)
* IAM least-privilege examples and testing instructions

## Quick-start (local test)

1. Configure AWS credentials with appropriate permissions.
2. Create S3 bucket, SNS topic, SQS queue, and an IAM role for Lambda (see Appendix).
3. Deploy Lambda (SAM/Console/CDK). Ensure S3 Event Notification points to Lambda for `s3:ObjectCreated:*`.
4. Upload a test file to the ingestion S3 prefix (e.g., `raw/`) and observe CloudWatch logs, SNS messages, and SQS messages.

---

# 2. Design Document

## Business requirements

* Real-time notification when new files are uploaded to S3.
* Validate file types and sizes; reject or quarantine invalid uploads.
* Capture and persist metadata for downstream processing.
* Ensure durability (use SQS + DLQ patterns) and observability.
* Strong security: encryption-at-rest, in-transit, and least-privilege IAM.

## Non-functional requirements

* Scale to thousands of uploads/minute.
* Low-latency (< 1s processing for typical files) for metadata pipeline.
* Retry and dead-letter handling for transient failures.
* Auditability and retention for compliance.

## High-level architecture

```
Client/App -> S3 (ingestion-bucket/raw/) -[S3 Event]-> Lambda Processor
 Lambda: validates -> publishes to SNS (alerting) -> sends metadata to SQS
 SQS -> downstream consumers (ETL, OCR, ML workers)
 SQS DLQ -> manual replay/alerting
 Monitoring: CloudWatch Logs, Metrics, Alarms; CloudTrail for API audit
 Storage Encryption: S3 SSE-KMS; KMS CMK for SQS/SNS payloads if needed
```

## Component details

### S3

* Bucket policy locks down `PutObject` to trusted principals/network.
* SSE-KMS enabled (SSE-KMS) with an audit CMK. Enforce object tagging.
* Lifecycle rules: move `raw/` older than X days to Glacier/infrequent access.
* Event Notification: `s3:ObjectCreated:*` with prefix filter e.g. `raw/` and suffix filter `.pdf`, `.csv`, etc. Target: Lambda or EventBridge.

### Lambda (s3_file_processor.py)

Responsibilities:

* Parse S3 event
* Download object **only** when necessary for validation (avoid large download when metadata suffices — use `head_object` to check size/Content-Type)
* Validate MIME type, size limits, and filename patterns
* Extract metadata (key, size, lastModified, uploader-from-metadata, tags)
* Publish an informative message to SNS (fan-out to teams/alerts)
* Push metadata payload to SQS for async downstream processing
* Tag object as `processed=true` or move invalid files to a quarantine prefix (copy+delete)
* Emit structured logs (JSON) to CloudWatch

Design choices:

* Keep Lambda short-lived and idempotent: use S3 ETag and a DynamoDB idempotency table if cross-invocation duplicate suppression required.
* Use environment variables for SNS topic ARN, SQS URL, allowed filetypes, size limits, quarantine prefix, and a CMK ARN for optional encryption.

### SQS

* Standard or FIFO depending on ordering needs. FIFO recommended when ordering per customer is needed.
* Visibility timeout set based on estimated downstream processing time.
* Redrive policy to DLQ after N failures.

### SNS

* Topic for human and system notifications (email, SMS, webhooks, or Lambda subscribers).
* Use message attributes for routing to endpoint filters.

### KMS

* Use a customer-managed CMK for S3 SSE-KMS and to encrypt sensitive metadata if required.

## Security & compliance

* IAM least-privilege: Lambda role allowed `s3:GetObject`, `s3:HeadObject`, `s3:PutObject` for quarantine prefix, `sqs:SendMessage`, `sns:Publish` only to specific resources. No wildcard actions.
* S3 bucket policy blocks public access and limits uploads to TLS and to known principals.
* Enable CloudTrail for S3 and KMS usage.
* Enable S3 Object Lock or retention policies if regulatory requirements apply.

## Observability & monitoring

* CloudWatch Logs with structured JSON logs from Lambda.
* Custom CloudWatch Metrics: `ProcessedFiles`, `InvalidFiles`, `SQSFail`, `QuarantineMoves`.
* Alarms for high DLQ depth, Lambda errors, or sudden drop in processed throughput.
* X-Ray tracing optional for distributed tracing across Lambda -> SQS consumers.

## Fault tolerance & failure modes

* Use DLQ for SQS messages; for Lambda processing errors, implement retries and durable moves to quarantine.
* For large file validation, perform `head_object` to avoid downloading entire file.
* If SNS publish fails, still attempt to push to SQS and vice versa; use a retry wrapper with exponential backoff.

## Cost considerations

* S3 storage and request costs, Lambda invocations & duration, SQS requests, SNS notifications.
* Use batch processing for downstream consumers to reduce SQS request counts.

---

# 3. Lambda — `s3_file_processor.py`

```python
# s3_file_processor.py
# Python 3.11
# Lambda entrypoint for S3 ObjectCreated events.

import os
import json
import logging
import boto3
import botocore
from typing import Dict, Any
from urllib.parse import unquote_plus
from datetime import datetime, timezone

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Environment variables
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN")
SQS_QUEUE_URL = os.environ.get("SQS_QUEUE_URL")
QUARANTINE_PREFIX = os.environ.get("QUARANTINE_PREFIX", "quarantine/")
MAX_FILE_SIZE_BYTES = int(os.environ.get("MAX_FILE_SIZE_BYTES", "10485760"))  # 10MB default
ALLOWED_CONTENT_TYPES = os.environ.get("ALLOWED_CONTENT_TYPES", "application/pdf,text/csv,application/json").split(',')
REGION = os.environ.get("AWS_REGION", "us-east-1")
DRY_RUN = os.environ.get("DRY_RUN", "false").lower() == "true"

s3 = boto3.client('s3', region_name=REGION)
sqs = boto3.client('sqs', region_name=REGION)
sns = boto3.client('sns', region_name=REGION)


class ValidationError(Exception):
    pass


def publish_sns(subject: str, message: Dict[str, Any], attributes: Dict[str, Any] = None) -> None:
    if not SNS_TOPIC_ARN:
        logger.warning("SNS_TOPIC_ARN not configured — skipping SNS publish")
        return
    try:
        kwargs = {
            'TopicArn': SNS_TOPIC_ARN,
            'Message': json.dumps(message, default=str),
            'Subject': subject[:100]
        }
        if attributes:
            # SNS message attributes must be in a specific format
            msg_attrs = {}
            for k, v in attributes.items():
                msg_attrs[k] = {
                    'DataType': 'String',
                    'StringValue': str(v)
                }
            kwargs['MessageAttributes'] = msg_attrs
        if DRY_RUN:
            logger.info("DRY_RUN SNS payload: %s", kwargs)
            return
        resp = sns.publish(**kwargs)
        logger.info("Published SNS messageId=%s", resp.get('MessageId'))
    except botocore.exceptions.ClientError as e:
        logger.exception("Failed to publish SNS message: %s", e)
        raise


def send_sqs_message(payload: Dict[str, Any]) -> None:
    if not SQS_QUEUE_URL:
        logger.warning("SQS_QUEUE_URL not configured — skipping SQS send")
        return
    try:
        body = json.dumps(payload, default=str)
        if DRY_RUN:
            logger.info("DRY_RUN SQS body: %s", body)
            return
        resp = sqs.send_message(QueueUrl=SQS_QUEUE_URL, MessageBody=body)
        logger.info("SQS send_message Id=%s", resp.get('MessageId'))
    except botocore.exceptions.ClientError as e:
        logger.exception("Failed to send message to SQS: %s", e)
        raise


def move_to_quarantine(bucket: str, key: str, reason: str) -> None:
    quarantine_key = f"{QUARANTINE_PREFIX}{key}"
    logger.info("Moving object to quarantine: s3://%s/%s -> s3://%s/%s", bucket, key, bucket, quarantine_key)
    if DRY_RUN:
        logger.info("DRY_RUN: would copy to quarantine and delete original")
        return
    try:
        s3.copy_object(Bucket=bucket,
                       CopySource={'Bucket': bucket, 'Key': key},
                       Key=quarantine_key)
        s3.delete_object(Bucket=bucket, Key=key)
        # Add quarantine reason as tag (best-effort — may be limited by permissions)
        try:
            s3.put_object_tagging(Bucket=bucket, Key=quarantine_key,
                                  Tagging={'TagSet': [{'Key': 'quarantine_reason', 'Value': reason}]})
        except Exception:
            logger.warning("Could not tag quarantined object; skipping tag")
    except botocore.exceptions.ClientError:
        logger.exception("Failed to move object to quarantine")
        raise


def validate_object_head(bucket: str, key: str) -> Dict[str, Any]:
    try:
        head = s3.head_object(Bucket=bucket, Key=key)
    except botocore.exceptions.ClientError as e:
        logger.exception("head_object failed for s3://%s/%s", bucket, key)
        raise

    content_type = head.get('ContentType')
    size = head.get('ContentLength')
    metadata = head.get('Metadata', {})

    logger.info("Object head: content_type=%s, size=%s", content_type, size)

    if content_type and content_type not in ALLOWED_CONTENT_TYPES:
        raise ValidationError(f"Disallowed content type: {content_type}")

    if size is not None and size > MAX_FILE_SIZE_BYTES:
        raise ValidationError(f"File too large: {size} bytes")

    # Return a minimal metadata dict
    return {
        'content_type': content_type,
        'size': size,
        'metadata': metadata,
        'etag': head.get('ETag')
    }


def build_payload(bucket: str, key: str, head: Dict[str, Any], event_time: str = None) -> Dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat()
    payload = {
        'file_name': key.split('/')[-1],
        's3_bucket': bucket,
        's3_key': key,
        'file_size_bytes': head.get('size'),
        'content_type': head.get('content_type'),
        'etag': head.get('etag'),
        'object_metadata': head.get('metadata', {}),
        'processed_timestamp': event_time or now
    }
    return payload


def lambda_handler(event, context):
    logger.info("Received event: %s", json.dumps(event))

    # S3 event parsing supports Records list
    records = event.get('Records', [])
    results = []

    for record in records:
        try:
            # Parse S3 record
            s3_info = record.get('s3', {})
            bucket = s3_info.get('bucket', {}).get('name')
            raw_key = s3_info.get('object', {}).get('key')
            if not bucket or not raw_key:
                logger.warning("Skipping record with no bucket/key")
                continue
            key = unquote_plus(raw_key)

            # Validate object using head_object (cheap)
            head = validate_object_head(bucket, key)

            # Build metadata payload
            event_time = record.get('eventTime')
            payload = build_payload(bucket, key, head, event_time)

            # Publish to SNS for notifications
            sns_subject = f"New file uploaded: {payload['file_name']}"
            publish_sns(sns_subject, {
                'summary': sns_subject,
                'details': payload
            }, attributes={'file_type': payload.get('content_type', 'unknown')})

            # Send to SQS for downstream processing
            send_sqs_message(payload)

            # Optionally: tag object as processed (best-effort)
            try:
                if not DRY_RUN:
                    s3.put_object_tagging(Bucket=bucket, Key=key,
                                          Tagging={'TagSet': [{'Key': 'processed', 'Value': 'true'}]})
            except Exception:
                logger.warning("Could not tag object as processed")

            results.append({'s3_bucket': bucket, 's3_key': key, 'status': 'processed'})

        except ValidationError as v:
            logger.warning("Validation error for %s/%s: %s", bucket, key, str(v))
            # Move to quarantine
            try:
                move_to_quarantine(bucket, key, reason=str(v))
            except Exception:
                logger.exception("Failed to move invalid object to quarantine")
            # Notify ops
            publish_sns(f"Quarantined file: {key}", {'reason': str(v), 's3_bucket': bucket, 's3_key': key})
            results.append({'s3_bucket': bucket, 's3_key': key, 'status': 'quarantined', 'reason': str(v)})

        except Exception as e:
            logger.exception("Unhandled exception processing s3://%s/%s", bucket if 'bucket' in locals() else 'unknown', key if 'key' in locals() else 'unknown')
            # Optionally: send a critical SNS or push a minimal failure message to SQS DLQ channel
            publish_sns("Processing error", {'error': str(e), 'record': record})
            results.append({'s3_bucket': bucket if 'bucket' in locals() else None, 's3_key': key if 'key' in locals() else None, 'status': 'error', 'error': str(e)})

    return {
        'statusCode': 200,
        'body': json.dumps({'results': results})
    }
```

---

# 4. Deployment options (snippets)

## AWS SAM (template snippet)

```yaml
Resources:
  FileProcessorFunction:
    Type: AWS::Serverless::Function
    Properties:
      Handler: s3_file_processor.lambda_handler
      Runtime: python3.11
      Role: arn:aws:iam::123456789012:role/FileProcessorLambdaRole
      Environment:
        Variables:
          SNS_TOPIC_ARN: !Ref FileEventsTopic
          SQS_QUEUE_URL: !Ref FileMetadataQueue
          QUARANTINE_PREFIX: "quarantine/"
          MAX_FILE_SIZE_BYTES: 10485760
      Events:
        S3Upload:
          Type: S3
          Properties:
            Bucket: my-ingestion-bucket
            Events: s3:ObjectCreated:*
            Filter:
              S3Key:
                Rules:
                  - Name: prefix
                    Value: raw/

  FileEventsTopic:
    Type: AWS::SNS::Topic

  FileMetadataQueue:
    Type: AWS::SQS::Queue

  FileMetadataQueueDLQ:
    Type: AWS::SQS::Queue

Outputs:
  LambdaFunctionArn:
    Value: !GetAtt FileProcessorFunction.Arn
```

## CDK (TypeScript) — high level

* Create S3 bucket with event notifications to Lambda
* Use `aws-lambda` + `aws-sns` + `aws-sqs` constructs
* Attach least-privilege IAM statements

## Terraform pointers

* Use `aws_s3_bucket_notification` to connect S3 -> Lambda
* Create `aws_lambda_function`, `aws_sqs_queue`, `aws_sns_topic`

---

# 5. Appendix

## Minimal IAM Role for Lambda (least-privilege)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:HeadObject",
        "s3:PutObject",
        "s3:PutObjectTagging",
        "s3:DeleteObject"
      ],
      "Resource": ["arn:aws:s3:::my-ingestion-bucket/*"]
    },
    {
      "Effect": "Allow",
      "Action": ["sqs:SendMessage"],
      "Resource": ["arn:aws:sqs:us-east-1:123456789012:FileMetadataQueue"]
    },
    {
      "Effect": "Allow",
      "Action": ["sns:Publish"],
      "Resource": ["arn:aws:sns:us-east-1:123456789012:FileEventsTopic"]
    },
    {
      "Effect": "Allow",
      "Action": ["kms:Decrypt","kms:Encrypt","kms:GenerateDataKey"],
      "Resource": ["arn:aws:kms:us-east-1:123456789012:key/your-cmk-id"]
    },
    {
      "Effect": "Allow",
      "Action": ["logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents"],
      "Resource": ["arn:aws:logs:*:*:*"]
    }
  ]
}
```

## Sample SQS message (from Lambda)

```json
{
  "file_name": "invoice_2025_11_05.pdf",
  "s3_bucket": "company-documents",
  "s3_key": "raw/invoices/invoice_2025_11_05.pdf",
  "file_size_bytes": 123456,
  "content_type": "application/pdf",
  "etag": '"abc123"',
  "object_metadata": {},
  "processed_timestamp": "2025-11-05T16:22:14.123456+00:00"
}
```

## Testing from CLI (simulate S3 put)

```bash
aws s3 cp ./testdata/sample.pdf s3://my-ingestion-bucket/raw/invoice_2025_11_05.pdf
```

Watch CloudWatch logs for Lambda output, check SNS subscriptions and SQS queue.

---

# Next steps (optional deliverables)

* Full CDK project (TypeScript/Python) with proper constructs
* Unit tests for Lambda (pytest + moto mocks)
* Integration test harness using LocalStack
* Terraform modules for infra as code

---

# License

MIT

---

*End of canvas document.*
