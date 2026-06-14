 
import boto3
import json
from botocore.exceptions import ClientError
from datetime import datetime

RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

s3 = boto3.client('s3')

def check_public_access(bucket_name):
    try:
        response = s3.get_public_access_block(Bucket=bucket_name)
        config = response['PublicAccessBlockConfiguration']
        if all(config.values()):
            return {"check": "Public Access", "status": "PASS", "detail": "All public access blocked", "risk": "None"}
        return {"check": "Public Access", "status": "FAIL", "detail": "Public access NOT blocked!", "risk": "HIGH"}
    except ClientError:
        return {"check": "Public Access", "status": "FAIL", "detail": "No public access block configured", "risk": "HIGH"}

def check_encryption(bucket_name):
    try:
        response = s3.get_bucket_encryption(Bucket=bucket_name)
        rules = response['ServerSideEncryptionConfiguration']['Rules']
        algo = rules[0]['ApplyServerSideEncryptionByDefault']['SSEAlgorithm']
        return {"check": "Encryption", "status": "PASS", "detail": f"Encrypted with {algo}", "risk": "None"}
    except ClientError:
        return {"check": "Encryption", "status": "FAIL", "detail": "No encryption configured!", "risk": "HIGH"}

def check_versioning(bucket_name):
    response = s3.get_bucket_versioning(Bucket=bucket_name)
    status = response.get('Status', 'Disabled')
    if status == 'Enabled':
        return {"check": "Versioning", "status": "PASS", "detail": "Versioning is enabled", "risk": "None"}
    return {"check": "Versioning", "status": "FAIL", "detail": "Versioning is OFF", "risk": "MEDIUM"}

def check_logging(bucket_name):
    response = s3.get_bucket_logging(Bucket=bucket_name)
    if 'LoggingEnabled' in response:
        target = response['LoggingEnabled']['TargetBucket']
        return {"check": "Logging", "status": "PASS", "detail": f"Logging to {target}", "risk": "None"}
    return {"check": "Logging", "status": "FAIL", "detail": "Access logging is DISABLED", "risk": "MEDIUM"}

def check_bucket_policy(bucket_name):
    try:
        response = s3.get_bucket_policy(Bucket=bucket_name)
        policy = json.loads(response['Policy'])
        for stmt in policy.get('Statement', []):
            if stmt.get('Effect') == 'Allow' and stmt.get('Principal') == '*':
                return {"check": "Bucket Policy", "status": "FAIL", "detail": "Policy allows PUBLIC access!", "risk": "HIGH"}
        return {"check": "Bucket Policy", "status": "PASS", "detail": "Policy looks restrictive", "risk": "None"}
    except ClientError:
        return {"check": "Bucket Policy", "status": "INFO", "detail": "No bucket policy attached", "risk": "LOW"}

def run_audit():
    print(f"\n{BOLD}{BLUE}{'='*55}{RESET}")
    print(f"{BOLD}  Cloud Misconfiguration Hunt - S3 Audit{RESET}")
    print(f"{BOLD}  Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RESET}")
    print(f"{BOLD}{BLUE}{'='*55}{RESET}\n")

    buckets = s3.list_buckets()['Buckets']
    print(f"Found {len(buckets)} bucket(s) to audit...\n")

    report = []

    for bucket in buckets:
        name = bucket['Name']
        print(f"{BOLD}Bucket: {name}{RESET}")
        print("-" * 50)

        checks = [
            check_public_access(name),
            check_encryption(name),
            check_versioning(name),
            check_logging(name),
            check_bucket_policy(name),
        ]

        report.append({"bucket": name, "checks": checks})

        for result in checks:
            icon  = "PASS" if result['status'] == 'PASS' else ("FAIL" if result['status'] == 'FAIL' else "INFO")
            color = GREEN if result['status'] == 'PASS' else (RED if result['status'] == 'FAIL' else YELLOW)
            risk  = f" [{result['risk']}]" if result['risk'] != "None" else ""
            print(f"  {color}[{icon}]{RESET} {result['check']:<20} {result['detail']}{RED}{risk}{RESET}")
        print()

    report_file = f"audit_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)
    print(f"{GREEN}Report saved to: {report_file}{RESET}\n")

if __name__ == "__main__":
    run_audit()