provider "aws"  {

  region = "eu-west-2"

}

resource "aws_default_vpc" "default" {

  // This is executed first as there should not be access to and from the internet at anypoint, so this should be done
  //first as there could be connections made during the period where all of the infrastructure is being set up.

  // Due to the nature of the "aws_default_vpc", as terraform does not create it, and instead 'adopts' it, you cannot directly
  // delete a default vpc using terraform at this time.
  // (https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/default_vpc)

  // As there are only 3 (4 including tags) options available within this resource (enable_dns_support, enable_dns_hostnames and enable_classiclink),
  // two of which are related to the accessibility of DNS within the VPC (enable_dns_support and enable_dns_hostnames), and one
  // which is already set to false by default (enable_dns_hostnames), I thought it would be best to set "enable_dns_support"
  // to false (default=true). This way there will be DNS resolving issues when traffic comes through. This is not a
  // great idea as traffic should not be able to get as far as it will with this solution, but it is the only attempt I could
  // make for part 7 of the test. Further more this is only for 1 default vpc, not the default vpcs in every region.

  enable_dns_support = false
}

resource "aws_s3_bucket" "logs_for_cloudtrail_storage_bucket" {
  // This S3 bucket's purpose is to contain the logs for changes made to the cloudtrail storage bucket

  // AWS Recommends that there there be a dedicated bucket for CloudWatch logs
  // Seen here: https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/S3ExportTasksConsole.html

  bucket = "cloudtrail-log-bucket-dh-7212381426721368712312873"
  acl    = "log-delivery-write"
  force_destroy=true

}

resource "aws_s3_bucket" "cloudtrail_storage_bucket" {
  //  Create S3 bucket to store cloudtrail logs

  bucket = "cloudtrail-storage-bucket-dh-7212381426721368712312873"
  force_destroy=true

  versioning {
    enabled = true
  }

  logging {
    target_bucket = aws_s3_bucket.logs_for_cloudtrail_storage_bucket.id
    target_prefix = "log/"
  }

}

data "aws_caller_identity" "current" {}
// The aws caller identity data source above is required to gain access to the callers account id, which would be used
// within the putObject for the S3_bucket policy (this is declared in the next resource)
// this is used within the resource argument where:
// Resource: "arn:aws:s3:::[...]/AWSLogs/${data.aws_caller_identity.current.account_id}/*",

resource "aws_s3_bucket_policy" "S3_policy_for_cloudtrail_bucket" {

  // The aws s3 bucket policy resource is created to allow cloudtrail access to the bucket to read the access control list
  // and to have permissions to write to the S3 bucket. This is in addition to allowing for logs to placed within
  // the bucket, provided the entity writing to the bucket is the bucket owner.

  bucket = aws_s3_bucket.cloudtrail_storage_bucket.id

  // below has been adapted from:
  // https://docs.aws.amazon.com/awscloudtrail/latest/userguide/create-s3-bucket-policy-for-cloudtrail.html
  policy = jsonencode({
    "Version": "2012-10-17",
    "Statement": [

        {
            Sid: "AWSCloudTrailAclCheck",
            Effect: "Allow",
            Principal: {
              Service: "cloudtrail.amazonaws.com"
            },
            Action: [
              "s3:GetBucketAcl",
            ],
            Resource: "arn:aws:s3:::${aws_s3_bucket.cloudtrail_storage_bucket.id}",
        },
        {
            Sid: "AWSCloudTrailWrite",
            Effect: "Allow",
            Principal: {
              Service: "cloudtrail.amazonaws.com"
            },
            Action: "s3:PutObject",
            Resource: "arn:aws:s3:::${aws_s3_bucket.cloudtrail_storage_bucket.id}/prefix/AWSLogs/${data.aws_caller_identity.current.account_id}/*",
            Condition: {
                StringEquals: {
                    "s3:x-amz-acl": "bucket-owner-full-control"
                }
            }
        }
    ]

  })
}

resource "aws_s3_bucket_public_access_block" "s3_block_public_access" {
  // This resource is created to ensure that public access to the bucket is blocked.
  // Researched here: https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_account_public_access_block

  bucket = aws_s3_bucket.cloudtrail_storage_bucket.id

  block_public_acls = true
  block_public_policy = true
  ignore_public_acls = true
  restrict_public_buckets = true

  depends_on = [
    aws_s3_bucket_policy.S3_policy_for_cloudtrail_bucket
  ]
}

resource "aws_cloudwatch_log_group" "integrate_with_cloudwatch_logs" {
  // This resource was created in order to provide a log group for the cloudwatch log metric filter resources (seen later)

  name = "cloudwatch_logs_integration"
}

resource "aws_kms_key" "KMS_key" {
  // As the KMS key will be provided by the customer, this resource has been created to be used as a placeholder

  description = "<This resource was created to act as a placeholder for a CMK>"
}

resource "aws_iam_role" "cloudtrail_role" {
  // An iam role is created to allow for a service (cloudwatch, as seen later) to have the ability to assume the role
  // of cloudtrail

  assume_role_policy = jsonencode({
    Version:  "2012-10-17"
    Statement: [
      {
        Action = "sts:AssumeRole"
        Effect: "Allow",
        Principal = {
          Service: "cloudtrail.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "role_policy_to_allow_for_cloudwatch_to_access_logs" {
  // This policy allows for cloudwatch to assume the role of cloudtrail to gain access to the logs that are held
  // in the cloudwatch log group

    name = "cloudwatch-log-role-policy"
    role = "${aws_iam_role.cloudtrail_role.id}"
    policy = jsonencode({

      "Version": "2012-10-17",
      "Statement": [
          {
              Effect: "Allow",
              Action: "logs:*",
              Resource: "${aws_cloudwatch_log_group.integrate_with_cloudwatch_logs.arn}*"
          }
      ]
    })
}

resource "aws_cloudtrail" "cloud_trail_local_name" {
  // Cloudtrail service is defined and created here

  name                          = "cloud-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_storage_bucket.id
  s3_key_prefix                 = "prefix"

  is_multi_region_trail = true
  enable_log_file_validation = true
  include_global_service_events = true
//  kms_key_id = aws_kms_key.KMS_key.arn // This needed to be commented out as the placeholder does not represent a complete Key, so terraform apply cannot be executed with it
  enable_logging = true

  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.integrate_with_cloudwatch_logs.arn}:*"
  // From "Sending Events to CloudWatch Logs" in "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudtrail"
  cloud_watch_logs_role_arn = aws_iam_role.cloudtrail_role.arn

  event_selector {
    include_management_events = true
    read_write_type = "All" // default value is "All" (both read/write is enabled)
  }

  depends_on = [
    aws_s3_bucket_policy.S3_policy_for_cloudtrail_bucket
  ]
}

resource "aws_sns_topic" "sns_for_cloudwatch_alarm" {
  // Create an SNS topic so that it can be used as subscription for an email later
  name = "cloudwatch_alarm_SNS"
}

resource "aws_sns_topic_subscription" "subscribe_to_cloudwatch_alarm_with_email" {
  // Create a subscription for a configured email. This is where the alarms will be sent to

  endpoint = "configuredEmailAddress@email.com"
  protocol = "email"
  topic_arn = "${aws_sns_topic.sns_for_cloudwatch_alarm.arn}"
}

// The following resources are both the filters and alarms for the following: unauthorized API calls,
// management console sign-in without MFA and usage of the root account.

// The way they have been declared is the filter is declared first and then subsequently by the alarm for the same
// event.

// The research for the cloudwatch log metric filters was done here:
// https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_metric_filter

// And the research for the cloudwatch metric alarms were done here:
// https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm

resource "aws_cloudwatch_log_metric_filter" "cloudwatch_unauthorizedAPICalls" {

  log_group_name = aws_cloudwatch_log_group.integrate_with_cloudwatch_logs.name
  name           = "cloudwatch_unauthorizedAPICalls"
  pattern        = "{ ($.errorCode = *UnauthorizedOperation) || ($.errorCode = AccessDenied*) }" // Filter pattern found here: https://docs.fugue.co/FG_R00055.html

  metric_transformation {
    name      = "cloudwatch_unauthorizedAPICalls_Event_Count"
    namespace = "metrics_for_cloudwatch_unauthorizedAPICalls" // https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/cloudwatch_concepts.html
    value     = "1"
  }
}


resource "aws_cloudwatch_metric_alarm" "alarm_for_unauthorizedAPICalls" {

  alarm_name = "unauthorizedAPICalls_alarm"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods = 1
  namespace = "MetricsForCloudwatchAlarm"

  period = "60"
  statistic = "Sum"
  metric_name = "MetricsForCloudTrail"

  threshold = "0"
  alarm_actions = ["${aws_sns_topic.sns_for_cloudwatch_alarm.arn}"]
}

resource "aws_cloudwatch_log_metric_filter" "cloudwatch_login_without_MFA" {
  log_group_name = aws_cloudwatch_log_group.integrate_with_cloudwatch_logs.name
  name = "cloudwatch_login_without_MFA"
  pattern = "{ ($.eventName = ConsoleLogin) && ($.additionalEventData.MFAUsed = No) }"

  metric_transformation {
    name = "cloudwatch_alarm_for_login_without_MFA_count"
    namespace = "metrics_for_cloudwatch_watch_for_login_without_MFA"
    value = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "alarm_for_login_without_MFA" {
  alarm_name = "login_without_MFA_alarm"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods = 1
  namespace = "MetricsForCloudwatchAlarm"

  period = "60"
  statistic = "Sum"
  metric_name = "MetricsForCloudTrail"

  threshold = "0"

  alarm_actions = ["${aws_sns_topic.sns_for_cloudwatch_alarm.arn}"]
}

resource "aws_cloudwatch_log_metric_filter" "cloudwatch_root_user_used" {
  log_group_name = aws_cloudwatch_log_group.integrate_with_cloudwatch_logs.name
  name = "cloudwatch_root_user_used"
  pattern = "{$.userIdentity.type = Root}"
  metric_transformation {
    name = "cloudwatch_root_user_used_count"
    namespace = "metrics_for_cloudwatch_root_user_used"
    value = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "alarm_for_root_user_used" {

  alarm_name = "root_user_used_alarm"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods = 1
  namespace = "MetricsForCloudwatchAlarm"

  period = "60"
  statistic = "Sum"
  metric_name = "MetricsForCloudTrail"

  threshold = "0"

  alarm_actions = ["${aws_sns_topic.sns_for_cloudwatch_alarm.arn}"]
}

