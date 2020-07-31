# infrastructure
This repository holds terraform templates to build AWS VPC

# build
1. Download terraform from https://www.terraform.io/downloads.html
2. ./terraform init
3. ./terraform validate
4. ./terraform plan
5. ,/terraform apply
6. ./terraform destroy

# Command to generate Certificate ARN by importing it to AWS ACM:
sudo aws acm import-certificate
--certificate fileb://certificate.pem
--certificate-chain fileb://certificate_bundle_chain.pem
--private-key fileb://~/aws-ssl-csr-private-key.pem
--profile [profile-name]
