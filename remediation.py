import boto3
from botocore.exceptions import ClientError

s3 = boto3.client('s3')

def fix_public_access(bucket_name):
    s3.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            'BlockPublicAcls': True,
            'IgnorePublicAcls': True,
            'BlockPublicPolicy': True,
            'RestrictPublicBuckets': True
        }
    )
    print(f"  [FIXED] Public access blocked on {bucket_name}")

def fix_versioning(bucket_name):
    s3.put_bucket_versioning(
        Bucket=bucket_name,
        VersioningConfiguration={'Status': 'Enabled'}
    )
    print(f"  [FIXED] Versioning enabled on {bucket_name}")

buckets = s3.list_buckets()['Buckets']
print("\nApplying fixes to all buckets...\n")

for bucket in buckets:
    name = bucket['Name']
    print(f"Bucket: {name}")
    fix_public_access(name)
    fix_versioning(name)
    print()

print("All fixes applied! Run s3_audit.py again to verify.\n")