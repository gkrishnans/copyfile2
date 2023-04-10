import botocore.exceptions
import argparse
import boto3
import csv
import os
from datetime import datetime
from botocore.exceptions import ClientError
from botocore.credentials import RefreshableCredentials
from botocore.session import get_session
from boto3 import Session

def is_bucket_public(bucket_name):
    try:
        bucket_acl = s3.get_bucket_acl(Bucket=bucket_name)
        for grant in bucket_acl["Grants"]:
            if grant["Grantee"]["Type"] == "Group" and (
                "AllUsers" in grant["Grantee"]["URI"]
                or "AuthenticatedUsers" in grant["Grantee"]["URI"]
            ):
                return "Public"
    except ClientError as e:
        if e.response["Error"]["Code"] == "AccessDenied":
            return "Access Denied"
        else:
            return "Unknown Error"
    return "Private"


def assumed_session(role_arn, session_name, session=None):
    """STS Role assume a boto3.Session                                                                                                                                                                                                                                                                                                                 
                                                                                                                                                                                                                                                                                                                                                       
    With automatic credential renewal.                                                                                                                                                                                                                                                                                                                 
                                                                                                                                                                                                                                                                                                                                                       
    Args:                                                                                                                                                                                                                                                                                                                                              
      role_arn: iam role arn to assume                                                                                                                                                                                                                                                                                                                 
      session_name: client session identifier                                                                                                                                                                                                                                                                                                          
      session: an optional extant session, note session is captured                                                                                                                                                                                                                                                                                    
               in a function closure for renewing the sts assumed role.                                                                                                                                                                                                                                                                                
                                                                                                                                                                                                                                                                                                                                                       
    Notes: We have to poke at botocore internals a few times                                                                                                                                                                                                                                                                                           
    """
    if session is None:
        session = Session()

    def refresh():
        credentials = session.client('sts', verify=False).assume_role(
            RoleArn=role_arn,
            RoleSessionName=session_name)['Credentials']
        return dict(
            access_key=credentials['AccessKeyId'],
            secret_key=credentials['SecretAccessKey'],
            token=credentials['SessionToken'],
            # Silly that we basically stringify so it can be parsed again                                                                                                                                                                                                                                                                              
            expiry_time=credentials['Expiration'].isoformat())

    session_credentials = RefreshableCredentials.create_from_metadata(
        metadata=refresh(),
        refresh_using=refresh,
        method='sts-assume-role')

    # so dirty.. it hurts, no clean way to set this outside of the internals poke                                                                                                                                                                                                                                                                      
    s = get_session()
    s._credentials = session_credentials
    region = session._session.get_config_variable('region') or 'us-east-1'
    s.set_config_variable('region', region)
    return Session(botocore_session=s)

# Define command-line arguments
parser = argparse.ArgumentParser(description="Check S3 bucket details")
parser.add_argument(
    "--buckets",
    metavar="bucket",
    nargs="*",
    help="list of bucket names to check (default: check all buckets)",
)

parser.add_argument(
    "--account_id",    
    help="ID of account to run the script against",
    required=True
)

# Get command-line arguments
args = parser.parse_args()

# Get the account ID
account_id = args.account_id
destination_bucket_name = 'rl-validation-report-bucket'

# Assume Role in target account for EBS volume describe
ec2_assume_role_arn = 'arn:aws:iam::' + account_id + ':role/S3RoleForEC2'

refresh_session = assumed_session(ec2_assume_role_arn, "ec2_assume_role")

# Create an S3 client
s3 = refresh_session.client(
    's3',
    verify=False
)    

# Get a list of all S3 buckets
if args.buckets:
    bucket_names = args.buckets
else:
    response = s3.list_buckets()
    bucket_names = [b["Name"] for b in response["Buckets"]]


# Checks if directory exists and creates if not
def check_dir(file_name: str):
    directory = os.path.dirname(file_name)
    if not os.path.exists(directory):
        os.makedirs(directory)


# Create directory as account_id and reports are created in each
dt = datetime.now()
seq = int(dt.strftime("%Y%m%d%H%M%S"))

dir_name = "/home/ec2-user/s3-reports/" + account_id + '_' + str(seq) + '_s3_details.csv'      
check_dir(dir_name)

# Open a CSV file to write the results to
with open(dir_name, "w", newline="", encoding="utf-8") as csvfile:
    writer = csv.writer(csvfile)

    # Write the header row to the CSV file
    writer.writerow(
        [
            "Bucket Name",
            "Encryption Status",
            "Object Key",
            "Object Encryption Status",
            "Storage Class",
            "Versioning Status",
            "Tags",
            "Has Lifecycle Policy",
            "Public Access",  # Added column for public access
            "Bucket Size (Bytes)",  # Added column for bucket size
            "Object Size (Bytes)",  # Added column for object size
        ]
    )

    # Loop through each bucket in the list
    for bucket_name in bucket_names:
        print(f"Validating bucket - {bucket_name}")
        try:
            # Check if the bucket is encrypted
            bucket_encryption = s3.get_bucket_encryption(Bucket=bucket_name)
            encryption_status = "Encrypted"
        except ClientError as e:
            if (
                e.response["Error"]["Code"]
                == "ServerSideEncryptionConfigurationNotFoundError"
            ):
                encryption_status = "Unencrypted"
            elif e.response["Error"]["Code"] == "AccessDenied":
                encryption_status = "Access Denied"
            else:
                encryption_status = "Unknown Error"

        # Get the S3 bucket versioning status
        try:
            bucket_versioning = s3.get_bucket_versioning(Bucket=bucket_name)
            if (
                "Status" in bucket_versioning
                and bucket_versioning["Status"] == "Enabled"
            ):
                versioning_status = "Enabled"
            else:
                versioning_status = "Not Enabled"
        except s3.exceptions.ClientError as e:
            if e.response["Error"]["Code"] == "AccessDenied":
                versioning_status = "Access Denied"
            else:
                raise e

        # Get the S3 bucket tags
        try:
            tags = s3.get_bucket_tagging(Bucket=bucket_name).get("TagSet")
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchTagSet":
                tags = None
            elif e.response["Error"]["Code"] == "AccessDenied":
                tags = "Access Denied"
            else:
                raise e

                # Get the S3 bucket lifecycle policy
        try:
            lifecycle = s3.get_bucket_lifecycle_configuration(Bucket=bucket_name)
            has_lifecycle_policy = True
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchLifecycleConfiguration":
                has_lifecycle_policy = False
            elif e.response["Error"]["Code"] == "AccessDenied":
                has_lifecycle_policy = "Access Denied"
            else:
                raise e

        if not tags:
            tag_string = "No Tags"
        elif tags == "Access Denied":
            tag_string = "Access Denied"
        else:
            tag_string = ""
            for tag in tags:
                tag_string += tag["Key"] + ":" + tag["Value"] + ", "
            tag_string = tag_string[:-2]

        # Check if the bucket is public or private
        public_access = is_bucket_public(bucket_name)

        # List all objects in the bucket and their encryption status
        try:
            objects = s3.list_objects_v2(Bucket=bucket_name)
        except:
            objects = {"Contents": []}

        if "Contents" in objects:
            bucket_size = 0  # Initialize bucket size to 0

            # Calculate the total size of the bucket
            for obj in objects["Contents"]:
                object_size = obj["Size"]  # Get object size
                bucket_size += object_size  # Add object size to bucket size

                object_key = obj["Key"]
                storage_class = obj["StorageClass"]
                object_size = obj["Size"]  # Get object size

                # Check if the storage class is defined
                if storage_class:
                    # Check the storage class of the object
                    if storage_class == "GLACIER":
                        storage_class = "Glacier"
                    elif storage_class == "DEEP_ARCHIVE":
                        storage_class = "Deep Archive"
                    elif storage_class == "STANDARD":
                        storage_class = "Standard"

                    try:
                        object_encryption = s3.get_object(
                            Bucket=bucket_name, Key=object_key
                        )
                        object_encryption_status = "Encrypted"
                    except ClientError as e:
                        if (
                            e.response["Error"]["Code"]
                            == "ServerSideEncryptionConfigurationNotFoundError"
                        ):
                            object_encryption_status = "Unencrypted"
                        elif e.response["Error"]["Code"] == "AccessDenied":
                            object_encryption_status = "Access Denied"
                        else:
                            object_encryption_status = "Unknown Error"

                    # Write the row to the CSV file
                    writer.writerow(
                        [
                            bucket_name,
                            encryption_status,
                            object_key,
                            object_encryption_status,
                            storage_class,
                            versioning_status,
                            tag_string,
                            has_lifecycle_policy,
                            public_access,  # Added value for public access
                            bucket_size,  # Display the total size of the bucket in all rows
                            object_size,  # Added value for object size
                        ]
                    )
        else:
            # Write the row to the CSV file
            writer.writerow(
                [
                    bucket_name,
                    encryption_status,
                    "",
                    "Unencrypted",
                    "",
                    versioning_status,
                    tag_string,
                    has_lifecycle_policy,
                    public_access,  # Added value for public access
                    0,  # Added value for empty bucket size
                    0,  # Added value for empty object size
                ]
            )

date = datetime.today().strftime('%Y-%m-%d')

# Key representing directory in S3 bucket
key = 's3-reports/'+ account_id + '/' + date + '.csv' 
s3 = boto3.resource('s3')
bucket = s3.Bucket(destination_bucket_name)

try:
    bucket.upload_file(dir_name, key)    
except botocore.exceptions.ClientError as e:
    print(e)
