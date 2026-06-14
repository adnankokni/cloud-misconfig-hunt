\# Cloud Misconfiguration Hunt



AWS S3 Security Audit Tool — SOC Analyst Portfolio Project



\## What This Does

Scans AWS S3 buckets for security misconfigurations including:

\- Public access exposure (HIGH)

\- Missing encryption (HIGH)

\- Versioning disabled (MEDIUM)

\- Logging disabled (MEDIUM)

\- Bucket policy issues (LOW)



\## Tools Used

\- Python 3

\- boto3 (AWS SDK)

\- AWS CLI

\- AWS S3 (Free Tier)



\## How To Run

pip install boto3

aws configure

python s3\_audit.py



\## Results

Found 4 misconfigurations across 3 buckets.

All remediated using remediation.py.

Re-audit confirmed all HIGH risks resolved.



\## Skills Demonstrated

\- Cloud security assessment

\- Python scripting and automation

\- AWS IAM and S3 configuration

\- Vulnerability detection and remediation

