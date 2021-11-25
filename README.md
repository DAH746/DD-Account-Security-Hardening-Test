# DD-Account-Security-Hardening-Test


# File Information
Task1TerraformFile.tf – Contains all the terraform code within a single file

dependency-list.txt – Contains all packages used

# Description

The purpose of this task was to demonstrate my ability to design, build and test some of the steps required to security harden an AWS account. The requirements were to:

1. Enable CloudTrail
    - Ensure CloudTrail is enabled in all regions
    - Ensure CloudTrail log file validation is enabled.
    - Ensure that both management and global events are captured within CloudTrail.
    - Ensure CloudTrail logs are encrypted at rest using KMS customer managed CMKs.

2. Ensure CloudTrail logs are stored within an S3 bucket.
    - Ensure controls are in place to block public access to the bucket.
    - Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket.
    - Ensure CloudTrail trails are integrated with CloudWatch Logs.

To send an email to a configured email address when any of the following events are logged within CloudTrail:

	3. Unauthorized API calls

	4. Management Console sign-in without MFA

	5. Usage of the "root" account

6. Remove the default VPC within every region of the account.

# Documentation

## Preface / Prerequisites

In order to run this project, Terraform is required. There is a list of the packages that were used when developing this project, these can be found in “dependency-list.txt”. If you would like to replicate the exact environment then, with a packet manager of your choice, install the packages that are within this file.

At this moment in time, I have not been able to successfully receive emails from a cloudwatch alarm due to a breach in security rules. 

In order to use a configured email address please replace “configuredEmailAddress@email.com” found in “resource "aws_sns_topic_subscription" "subscribe_to_cloudwatch_alarm_with_email"” with the email of your choice.

My recommendation would be that, when reading the code, to also read the comments in a sequential manner as this will provide the reasoning behind each resource and their purposes in a more story-like manner. However, if you would like all of the documentation in one place then please continue reading.

In terms of the structure of the code, it has been structured in a way that I think makes sense in terms of both execution and similarity between the resources. For example, creating the S3 buckets together and then followed by S3 bucket policies, or creating an IAM role, followed by the use of this IAM role for the following IAM role policy and then the resource that uses this.

As mentioned previously, the code has comments that explain both the reasoning and purpose of each resource. These comments will be replicated here as they are comprehensive enough to be used in documentation. 

## Documentation of Code
The structure of the documentation of the code will be with the use of resource declarations, in the order they are present in the code, and then their respective comments underneath them. The idea is to provide an overview and to then be able to see the details of each resource within the code itself if you would like to see the details.

1. provider "aws"
2. resource "aws_default_vpc" "default"

    - This is executed first as there should not be access to and from the internet at anypoint, so this should be carried out first as there could be connections made during the period where all of the infrastructure is being set up. 
    
    - Due to the nature of the "aws_default_vpc", as terraform does not create it, and instead 'adopts' it, you cannot directly delete a default vpc using terraform at this time. (https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/default_vpc)
    
    - As there are only 3 (4 including tags) options available within this resource (enable_dns_support, enable_dns_hostnames and enable_classiclink), two of which are related to the accessibility of DNS within the VPC (enable_dns_support and enable_dns_hostnames), and one which is already set to false by default (enable_dns_hostnames), I thought it would be best to set "enable_dns_support" to false (default=true). This way there will be DNS resolving issues when traffic comes through. This is not a great idea as traffic should not be able to get as far as it will with this solution, but it is the only attempt I could make for part 7 of the test. Furthermore, this is only for one default vpc, not the default vpcs in every region.

3. resource "aws_s3_bucket" "logs_for_cloudtrail_storage_bucket"
	- This S3 bucket's purpose is to contain the logs for changes made to the cloudtrail storage bucket. AWS Recommends that there be a dedicated bucket for CloudWatch logs. Seen here: https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/S3ExportTasksConsole.html

4. resource "aws_s3_bucket" "cloudtrail_storage_bucket"
	- Create S3 bucket to store cloudtrail logs

5. data "aws_caller_identity" "current"
	- The aws caller identity data source above is required to gain access to the caller’s account id, which would be used within the putObject for the S3_bucket policy (this is declared in the next resource). This is used within the resource argument: "arn:aws:s3:::[...]/AWSLogs/${data.aws_caller_identity.current.account_id}/*". Where "${data.aws_caller_identity.current.account_id}" contains the account ID.

6. resource "aws_s3_bucket_policy" "S3_policy_for_cloudtrail_bucket"
 	- The aws s3 bucket policy resource is created to allow cloudtrail access to the bucket in order to read the access control list as well as to have permissions to write to the S3 bucket. This is in addition to allowing for logs to be placed within the bucket, provided the entity writing to the bucket is the bucket owner.

7. resource "aws_s3_bucket_public_access_block" "s3_block_public_access"
	- This resource is created to ensure that public access to the bucket is blocked.

8. resource "aws_cloudwatch_log_group" "integrate_with_cloudwatch_logs"
	- This resource was created in order to provide a log group for the cloudwatch log metric filter resources (seen later)

9. resource "aws_kms_key" "KMS_key" 
	- As the KMS key will be provided by the customer, this resource has been created to be used as a placeholder

10. resource "aws_iam_role" "cloudtrail_role"
	- An iam role is created to allow for a service (cloudwatch, as seen later) to have the ability to assume the role of cloudtrail

11. resource "aws_iam_role_policy" "role_policy_to_allow_for_cloudwatch_to_access_logs"
	- This policy allows for cloudwatch to assume the role of cloudtrail to gain access to the logs that are held in the cloudwatch log group

12. resource "aws_cloudtrail" "cloud_trail_local_name"
	- Cloudtrail service is defined and created here

13. resource "aws_sns_topic" "sns_for_cloudwatch_alarm"
	- Create an SNS topic so that it can be used as subscription for an email later

14. resource "aws_sns_topic_subscription" "subscribe_to_cloudwatch_alarm_with_email"
	- Create a subscription for a configured email. This is where the alarms will be sent to

Please note, the following resources are both the filters and alarms for the following: unauthorized API calls, management console sign-in without MFA and usage of the root account. The way they have been declared is the filter is declared first and then subsequently by the alarm for the same event.

15. resource "aws_cloudwatch_log_metric_filter" "cloudwatch_unauthorizedAPICalls"

16. resource "aws_cloudwatch_metric_alarm" "alarm_for_unauthorizedAPICalls"

17. resource "aws_cloudwatch_log_metric_filter" "cloudwatch_login_without_MFA"

18. resource "aws_cloudwatch_metric_alarm" "alarm_for_login_without_MFA"

19. resource "aws_cloudwatch_log_metric_filter" "cloudwatch_root_user_used"

20. resource "aws_cloudwatch_metric_alarm" "alarm_for_root_user_used"
