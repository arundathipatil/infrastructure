provider "aws" {
  version = "~> 2.0"
  access_key = "${var.access_key_id}"
  secret_key = "${var.secret_key_id}"
  region = "${var.aws_region}"
}

# Create a new VPC
resource "aws_vpc" "csye6225_a4_vpc" {
  cidr_block           = "${var.vpc_cidr}"
  enable_dns_hostnames = true
  enable_dns_support = true
  enable_classiclink_dns_support = true
  assign_generated_ipv6_cidr_block = false

  tags = {
    Name = "csye6225_a4_vpc",
    Tag2 = "new tag"
  }
}

# Create Internet Gateway
resource "aws_internet_gateway" "csye6225_a4_Gateway" {
 vpc_id = "${aws_vpc.csye6225_a4_vpc.id}"
 tags = {
        Name = "csye6225_a4_Gateway"
  }
}

# create a new Subnet
resource "aws_subnet" "csye6225_a4_Subnet1" {
  vpc_id                  = "${aws_vpc.csye6225_a4_vpc.id}"
  cidr_block              = "${var.subnet1_cidr}"
  availability_zone       = "${var.availabilityZone1}"
  map_public_ip_on_launch = true
  tags = {
   Name = "csye6225_a4_Subnet1"
  }
}

# create a new Subnet 2
resource "aws_subnet" "csye6225_a4_Subnet2" {
  vpc_id                  = "${aws_vpc.csye6225_a4_vpc.id}"
  cidr_block              = "${var.subnet2_cidr}"
  availability_zone       = "${var.availabilityZone2}"
  map_public_ip_on_launch = true
  tags = {
   Name = "csye6225_a4_Subnet2"
  }
}


# create a new Subnet 3
resource "aws_subnet" "csye6225_a4_Subnet3" {
  vpc_id                  = "${aws_vpc.csye6225_a4_vpc.id}"
  cidr_block              = "${var.subnet3_cidr}"
  availability_zone       = "${var.availabilityZone3}"
  map_public_ip_on_launch = true  
  tags = {
   Name = "csye6225_a4_Subnet3"
  }
}

# Create Route Table
resource "aws_route_table" "csye6225_a4_route_table" {
 vpc_id = "${aws_vpc.csye6225_a4_vpc.id}"
 route {
    cidr_block = "${var.routeTable_cidr}"
    gateway_id = "${aws_internet_gateway.csye6225_a4_Gateway.id}"
  }
}

resource "aws_route_table_association" "csye6225_route_table_subnet1" {
  subnet_id      = "${aws_subnet.csye6225_a4_Subnet1.id}"
  route_table_id = "${aws_route_table.csye6225_a4_route_table.id}"
}

resource "aws_route_table_association" "csye6225_route_table_subnet2" {
  subnet_id      = "${aws_subnet.csye6225_a4_Subnet2.id}"
  route_table_id = "${aws_route_table.csye6225_a4_route_table.id}"
}

resource "aws_route_table_association" "csye6225_route_table_subnet3" {
  subnet_id      = "${aws_subnet.csye6225_a4_Subnet3.id}"
  route_table_id = "${aws_route_table.csye6225_a4_route_table.id}"
}

resource "aws_security_group" "application" {
  name        = "application"
  description = "Allow TLS inbound traffic"
  vpc_id      = "${aws_vpc.csye6225_a4_vpc.id}"

  # ingress {
  #   description = "TLS from VPC-Https"
  #   from_port   = 443
  #   to_port     = 443
  #   protocol    = "tcp"
  #   cidr_blocks = ["${var.allow-all}"]
  # }

  # ingress {
  #   description = "TLS from VPC-HTTP"
  #   from_port   = 80
  #   to_port     = 80
  #   protocol    = "tcp"
  #   cidr_blocks = ["${var.allow-all}"]
  # }

  # ingress {
  #   description = "TLS from VPC-Custom TCP"
  #   from_port   = 8080
  #   to_port     = 8080
  #   protocol    = "tcp"
  #   cidr_blocks = ["${var.allow-all}"]
  # }

  # ingress {
  #   description = "TLS from VPC-SSH"
  #   from_port   = 22
  #   to_port     = 22
  #   protocol    = "tcp"
  #   cidr_blocks = ["${var.allow-all}"]
  # }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "application"
  }
}

# resource "aws_security_group_rule" "application_security_group_rule" {
#   type              = "ingress"
#   from_port         = 22
#   to_port           = 22
#   protocol          = "tcp"
#   cidr_blocks       = ["0.0.0.0/0", "::/0"]
#   security_group_id = "${aws_security_group.application.id}"
# }


resource "aws_security_group" "database" {
  name        = "database"
  description = "Allow TLS inbound traffic"
  vpc_id      = "${aws_vpc.csye6225_a4_vpc.id}"

  # ingress {
  #   description = "TLS from VPC-mysql"
  #   from_port   = 3306
  #   to_port     = 3306
  #   protocol    = "tcp"
  #   cidr_blocks = ["0.0.0.0/0"]
  # }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "database"
  }
}

resource "aws_security_group_rule" "databaseSecurityGroupRule" {
  type              = "ingress"
  from_port         = 3306
  to_port           = 3306
  protocol          = "tcp"
  security_group_id = "${aws_security_group.database.id}"
  # cidr_blocks = ["0.0.0.0/0"]
  source_security_group_id = "${aws_security_group.application.id}"
}

resource "aws_kms_key" "mykey" {
  description             = "This key is used to encrypt bucket objects"
  # deletion_window_in_days = 30
}

// Create S3 bucket to save webapp book images
resource "aws_s3_bucket" "webapp_arundathi_patil" {
  bucket = "webapp.arundathi.patil"
  acl    = "private"
  force_destroy = true
  tags = {
    Name        = "webapp.arundathi.patil"
    Environment = "Dev"
  }
  
  lifecycle_rule {
    id      = "log"
    enabled = true

    prefix = "log/"

    tags = {
      "rule"      = "log"
      "autoclean" = "true"
    }
    transition {
      days          = 30
      storage_class = "STANDARD_IA" # or "ONEZONE_IA"
    }
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = "${aws_kms_key.mykey.arn}"
        sse_algorithm     = "aws:kms"
      }
    }
  }
}

resource "aws_db_subnet_group" "dbSubnetGroup" {
  name       = "main"
  subnet_ids = ["${aws_subnet.csye6225_a4_Subnet2.id}", "${aws_subnet.csye6225_a4_Subnet3.id}"]

  tags = {
    Name = "My DB subnet group"
  }
}

resource "aws_db_instance" "default" {
  allocated_storage    = 20
  storage_type         = "gp2"
  engine_version       = "5.7"
  # parameter_group_name = "default.mysql5.7"
  storage_encrypted    = true
  parameter_group_name = "${aws_db_parameter_group.param-group-for-rds.name}"
  engine               = "mysql"
  instance_class       = "db.t3.micro"
  multi_az             = false 
  identifier           = "csye6225-su2020"
  username             = "${var.database_username}"
  password             = "${var.database_password}"
  db_subnet_group_name = "${aws_db_subnet_group.dbSubnetGroup.name}"
  publicly_accessible  = false
  name                 = "csye6225"
  vpc_security_group_ids = ["${aws_security_group.database.id}"]
  skip_final_snapshot     = true
}

resource "aws_db_parameter_group" "param-group-for-rds" {
  name   = "param-group-for-rds"
  family = "MySQL5.7"

  parameter {
    name  = "performance_schema"
    value = "1"
    apply_method = "pending-reboot"
  }
}

resource "aws_key_pair" "csye6225_su20_a5" {
  key_name   = "csye6225_su20_a5"
  public_key = file("~/.ssh/csye6225_su20_a4.pub")
}



data "template_file" "init" {
  template = "${file("./userdata.sh")}"
  vars = {
    rds_endpoint = "${aws_db_instance.default.address}"
    ACCESS_KEY = "${var.access_key_id}"
    SECRET_KEY = "${var.secret_key_id}"
  }
}

// Creating EC2 instance
# resource "aws_instance" "csye6225Webapp" {
#   ami           = "${var.amiId}"
#   instance_type = "t2.micro"
#   disable_api_termination  = false
#   subnet_id = "${aws_subnet.csye6225_a4_Subnet1.id}"
#   iam_instance_profile = "${aws_iam_instance_profile.EC2Profile.name}"

#    root_block_device {
#     volume_size           = "${var.EC2_ROOT_VOLUME_SIZE}"
#     volume_type           = "${var.EC2_ROOT_VOLUME_TYPE}"
#     delete_on_termination = "${var.EC2_ROOT_VOLUME_DELETE_ON_TERMINATION}"
#   }
#   vpc_security_group_ids = ["${aws_security_group.application.id}"]
#   key_name = "${aws_key_pair.csye6225_su20_a5.key_name}"
#   user_data = "${data.template_file.init.rendered}"
#   tags = {
#     Name = "csye6225Webapp-ec2"
#   }
# }

resource "aws_dynamodb_table" "csye6225" {
  name           = "csye6225"
  billing_mode   = "PROVISIONED"
  read_capacity  = 20
  write_capacity = 20
  hash_key       = "id"

  attribute {
    name = "id"
    type = "S"
  }

  ttl {
    attribute_name = "TimeToExist"
    enabled        = true
  }

  tags = {
    Name        = "csye6225-ec2"
  }
}

// Create S3 bucket to save build artifacts- for EC2 Codedeploy to pick it
resource "aws_s3_bucket" "codedeploy_arundathipatil_me" {
  bucket = "codedeploy.arundathipatil.me"
  # acl    = "private"
  force_destroy = true
  tags = {
    Name        = "codedeploy.arundathipatil.me"
    Environment = "Prod"
  }
  
  lifecycle_rule {
    id      = "log"
    enabled = true

    prefix = "log/"

    tags = {
      "rule"      = "log"
      "autoclean" = "true"
    }
    transition {
      days          = 30
      storage_class = "STANDARD_IA" # or "ONEZONE_IA"
    }
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        # kms_master_key_id = "${aws_kms_key.mykey.arn}"
        sse_algorithm     = "AES256"
      }
    }
  }
}





// Policies


#Creating EC2 instance profile
resource "aws_iam_instance_profile" "EC2Profile" {
  name = "EC2Profile"
  # roles = ["${aws_iam_role.EC2-CSYE6225.name}", "${aws_iam_role.CodeDeployEC2ServiceRole.name}"]
  # role = "${aws_iam_role.CodeDeployEC2ServiceRole.name}"
  role = "${aws_iam_role.EC2ServiceRole.name}"
}

#Create EC2ServiceRole role
resource "aws_iam_role" "EC2ServiceRole" {
  name = "EC2ServiceRole"

  assume_role_policy = data.aws_iam_policy_document.ec2-instance-assume-role-policy.json

  tags = {
    tag-key = "tag-value"
  }
}

#assume_role_policy JSON data for EC2 
data "aws_iam_policy_document" "ec2-instance-assume-role-policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

#Create EC2-CSYE6225 role
# resource "aws_iam_role" "EC2-CSYE6225" {
#   name = "EC2-CSYE6225"

#   assume_role_policy = <<EOF
# {
#   "Version": "2012-10-17",
#   "Statement": [
#     {
#       "Action": "sts:AssumeRole",
#       "Principal": {
#         "Service": "ec2.amazonaws.com"
#       },
#       "Effect": "Allow",
#       "Sid": ""
#     }
#   ]
# }
# EOF

#   tags = {
#     tag-key = "tag-value"
#   }
# }

// CodeDeployEC2ServiceRole IAM Role for EC2 Instance(s)
resource "aws_iam_role" "CodeDeployEC2ServiceRole" {
  name = "CodeDeployEC2ServiceRole"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF

  tags = {
    tag-key = "tag-value"
  }
}

# resource "aws_iam_role_policy_attachment" "CodeDeployEC2ServiceRoleAttach" {
#   policy_arn = "${aws_iam_policy.CodeDeploy-EC2-S3.arn}"
#   role       = "${aws_iam_role.CodeDeployEC2ServiceRole.name}"
# }

#Create WebAppS3 Policy
resource "aws_iam_policy" "WebAppS3" {
  name        = "WebAppS3"
  # role        = "${aws_iam_role.EC2-CSYE6225.id}"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement":  [
        {
            "Effect": "Allow",
            "Action": [
                "s3:ListBucket"
            ],
            "Resource": [
                "arn:aws:s3:::webapp.arundathi.patil"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:PutObject",
                "s3:GetObject",
                "s3:DeleteObject"
            ],
            "Resource": [
                "arn:aws:s3:::webapp.arundathi.patil/*"
            ]
        }        
    ]
}
EOF
}

#Attaching WebAppS3 policy to EC2ServiceRole role
resource "aws_iam_role_policy_attachment" "WebAppS3_EC2ServiceRole_attach" {
  policy_arn = "${aws_iam_policy.WebAppS3.arn}"
  role = "${aws_iam_role.EC2ServiceRole.name}"
}
#-----------------------------------------------------------------------------------------------------------



// CodeDeploy S3 policy
resource "aws_iam_policy" "CodeDeploy-EC2-S3" {
  name        = "CodeDeploy-EC2-S3"
  # role        = "${aws_iam_role.CodeDeployEC2ServiceRole.id}"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement":  [
        {
            "Effect": "Allow",
            "Action": [
                "s3:*"
            ],
            "Resource": "*"
        }
    ]
}
EOF
}

#Attaching CodeDeploy-EC2-S3 policy to EC2ServiceRole role
resource "aws_iam_role_policy_attachment" "CodeDeploy-EC2-S3_EC2ServiceRole_attach" {
  policy_arn = "${aws_iam_policy.CodeDeploy-EC2-S3.arn}"
  role = "${aws_iam_role.EC2ServiceRole.name}"
}
#------------------------------------------------------------------------------------------------------------------


#CloudWatchAgent Policy

resource "aws_iam_policy" "cloudwatch-EC2" {
  name        = "cloudwatch-EC2"

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "cloudwatch:PutMetricData",
                "ec2:DescribeVolumes",
                "ec2:DescribeTags",
                "logs:PutLogEvents",
                "logs:DescribeLogStreams",
                "logs:DescribeLogGroups",
                "logs:CreateLogStream",
                "logs:CreateLogGroup"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "ssm:GetParameter"
            ],
            "Resource": "arn:aws:ssm:*:*:parameter/AmazonCloudWatch-*"
        }
    ]
}
EOF
}

#Attaching cloudwatch-EC2 policy to EC2ServiceRole role
resource "aws_iam_role_policy_attachment" "cloudwatch-EC2_EC2ServiceRole_attach" {
  policy_arn = "${aws_iam_policy.cloudwatch-EC2.arn}"
  role = "${aws_iam_role.EC2ServiceRole.name}"
}

#-------------------------------------------------------------------------------------------------------------
# AmazonSSMManagedInstanceCore  Policy

resource "aws_iam_policy" "Systems-Manager-EC2" {
  name        = "Systems-Manager-EC2"

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ssm:DescribeAssociation",
                "ssm:GetDeployablePatchSnapshotForInstance",
                "ssm:GetDocument",
                "ssm:DescribeDocument",
                "ssm:GetManifest",
                "ssm:GetParameter",
                "ssm:GetParameters",
                "ssm:ListAssociations",
                "ssm:ListInstanceAssociations",
                "ssm:PutInventory",
                "ssm:PutComplianceItems",
                "ssm:PutConfigurePackageResult",
                "ssm:UpdateAssociationStatus",
                "ssm:UpdateInstanceAssociationStatus",
                "ssm:UpdateInstanceInformation"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "ssmmessages:CreateControlChannel",
                "ssmmessages:CreateDataChannel",
                "ssmmessages:OpenControlChannel",
                "ssmmessages:OpenDataChannel"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "ec2messages:AcknowledgeMessage",
                "ec2messages:DeleteMessage",
                "ec2messages:FailMessage",
                "ec2messages:GetEndpoint",
                "ec2messages:GetMessages",
                "ec2messages:SendReply"
            ],
            "Resource": "*"
        }
    ]
}
EOF
}

#Attaching Systems-Manager-EC2 policy to EC2ServiceRole role
resource "aws_iam_role_policy_attachment" "Systems-Manager-EC2_EC2ServiceRole_attach" {
  policy_arn = "${aws_iam_policy.Systems-Manager-EC2.arn}"
  role = "${aws_iam_role.EC2ServiceRole.name}"
}


#------------------------------------------------------------------------------------------------------------------



// import CICD/circleci user
resource "aws_iam_user" "cicd" {
  name = "cicd"
}

//Policy to allow cicd user to upload objects to s3
resource "aws_iam_policy" "circleci-Upload-To-S3" {
  name        = "circleci-Upload-To-S3"
  description = "Allows cicd user to access S3 bucket to upload build artifacts"

   policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:ListBucket"
            ],
            "Resource": [
                "arn:aws:s3:::codedeploy.arundathipatil.me"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:PutObject",
                "s3:Get*",
                "s3:List*"
            ],
            "Resource": [
                "arn:aws:s3:::codedeploy.arundathipatil.me/*"
            ]
        }
    ]
}
EOF
}
// Attaching circleci-Upload-To-S3 to cicd user
resource "aws_iam_user_policy_attachment" "circleci-attach-upload-To-S3" {
  user       = "${aws_iam_user.cicd.name}"
  policy_arn = "${aws_iam_policy.circleci-Upload-To-S3.arn}"
}

#------------------------------------------------------------------------------------------------------
// CircleCI-Code-Deploy Policy for CircleCI to Call CodeDeploy. TO do
resource "aws_iam_policy" "circleci-Code-Deploy" {
  name        = "circleci-Code-Deploy"
  description = "Allows cicd user to call codedeply"

   policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
                "codedeploy:PutLifecycleEventHookExecutionStatus",
                "codedeploy:DeleteGitHubAccountToken",
                "codedeploy:BatchGetDeploymentTargets",
                "codedeploy:DeleteResourcesByExternalId",
                "codedeploy:GetDeploymentTarget",
                "codedeploy:StopDeployment",
                "codedeploy:ContinueDeployment",
                "codedeploy:ListDeploymentTargets",
                "codedeploy:ListApplications",
                "codedeploy:CreateCloudFormationDeployment",
                "codedeploy:ListOnPremisesInstances",
                "codedeploy:ListGitHubAccountTokenNames",
                "codedeploy:ListDeploymentConfigs",
                "codedeploy:SkipWaitTimeForInstanceTermination"
            ],
            "Resource": "*"
        },
        {
            "Sid": "VisualEditor1",
            "Effect": "Allow",
            "Action": "codedeploy:*",
            "Resource": [
                "arn:aws:codedeploy:us-east-1:371394122941:deploymentconfig:CodeDeployDefault.AllAtOnce",
                "arn:aws:codedeploy:us-east-1:371394122941:instance:csye6225Webapp-ec2",
                "arn:aws:codedeploy:us-east-1:371394122941:deploymentgroup:csye6225-webapp/csye6225-webapp-deployment",
                "arn:aws:codedeploy:us-east-1:371394122941:application:csye6225-webapp"
            ]
        }
    ]
}
EOF
}

// attaching code deploy policy to cicd user
resource "aws_iam_user_policy_attachment" "cicd-attach-Code-deploy" {
  user       = "${aws_iam_user.cicd.name}"
  policy_arn = "${aws_iam_policy.circleci-Code-Deploy.arn}"
}


#----------------------------------------------------------------------------------



// policy to allow cicd ci user to build a new ami in dev/prod account
resource "aws_iam_policy" "circleci-ec2-ami" {
  name        = "circleci-ec2-ami"
  description = "Allows cicd user to build new AMI"

   policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:AttachVolume",
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:CopyImage",
        "ec2:CreateImage",
        "ec2:CreateKeypair",
        "ec2:CreateSecurityGroup",
        "ec2:CreateSnapshot",
        "ec2:CreateTags",
        "ec2:CreateVolume",
        "ec2:DeleteKeyPair",
        "ec2:DeleteSecurityGroup",
        "ec2:DeleteSnapshot",
        "ec2:DeleteVolume",
        "ec2:DeregisterImage",
        "ec2:DescribeImageAttribute",
        "ec2:DescribeImages",
        "ec2:DescribeInstances",
        "ec2:DescribeInstanceStatus",
        "ec2:DescribeRegions",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeSnapshots",
        "ec2:DescribeSubnets",
        "ec2:DescribeTags",
        "ec2:DescribeVolumes",
        "ec2:DetachVolume",
        "ec2:GetPasswordData",
        "ec2:ModifyImageAttribute",
        "ec2:ModifyInstanceAttribute",
        "ec2:ModifySnapshotAttribute",
        "ec2:RegisterImage",
        "ec2:RunInstances",
        "ec2:StopInstances",
        "ec2:TerminateInstances"
      ],
      "Resource": "*"
    }
  ]
}
EOF
}

# Attach cicd-ec2-ami policy to cicd user
resource "aws_iam_user_policy_attachment" "circleci-attach-ec2-ami" {
  user       = "${aws_iam_user.cicd.name}"
  policy_arn = "${aws_iam_policy.circleci-ec2-ami.arn}"
}

#----------------------------------------------------------------------------------------------------------
// CodeDeployServiceRole
resource "aws_iam_role" "CodeDeployServiceRole" {
  name = "CodeDeployServiceRole"

  assume_role_policy = data.aws_iam_policy_document.codedeploy-assume-role-policy.json
}

#Policy document json data for CodeDeploy Service
data "aws_iam_policy_document" "codedeploy-assume-role-policy" {
 statement {
   actions = ["sts:AssumeRole"]

   principals {
     type        = "Service"
     identifiers = ["codedeploy.amazonaws.com"]
   }
 }
}


resource "aws_iam_role_policy_attachment" "AWSCodeDeployRoleAttach" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSCodeDeployRole"
  role       = "${aws_iam_role.CodeDeployServiceRole.name}"
}

#===================================================END OF POLICIES

// Codedeploy application
resource "aws_codedeploy_app" "csye6225-webapp" {
  compute_platform = "Server"
  name             = "csye6225-webapp"
}



//below code till line 644 creates clouddeploy deployment group
resource "aws_codedeploy_deployment_group" "csye6225-webapp-deployment" {
  app_name              = "${aws_codedeploy_app.csye6225-webapp.name}"
  deployment_group_name = "csye6225-webapp-deployment"
  service_role_arn      = "${aws_iam_role.CodeDeployServiceRole.arn}"
  autoscaling_groups = ["${aws_autoscaling_group.asg.name}"]

   deployment_style {
    deployment_option = "WITHOUT_TRAFFIC_CONTROL"
    deployment_type = "IN_PLACE"
  }

  ec2_tag_set {
    ec2_tag_filter {
      key   = "Name"
      type  = "KEY_AND_VALUE"
      value = "csye6225Webapp-ec2"
    }
  }

  auto_rollback_configuration {
    enabled = true
    events  = ["DEPLOYMENT_FAILURE"]
  }
}

//-------------------------------------------------------------------------------------------------------

// Creating launch configuration
resource "aws_launch_configuration" "asg_launch_config" {
  name = "asg_launch_config"
  image_id      = "${var.amiId}"
  instance_type = "t2.micro"
  key_name = "${aws_key_pair.csye6225_su20_a5.key_name}"
  associate_public_ip_address = true
  user_data = "${data.template_file.init.rendered}"
  iam_instance_profile = "${aws_iam_instance_profile.EC2Profile.name}"
  security_groups = ["${aws_security_group.application.id}"]
   root_block_device {
    volume_size           = "${var.EC2_ROOT_VOLUME_SIZE}"
    volume_type           = "${var.EC2_ROOT_VOLUME_TYPE}"
    delete_on_termination = "${var.EC2_ROOT_VOLUME_DELETE_ON_TERMINATION}"
  }

  lifecycle {
    create_before_destroy = true
  }
}

// Auto scaling group for EC2
resource "aws_autoscaling_group" "asg" {
  name                 = "asg"
  launch_configuration = "${aws_launch_configuration.asg_launch_config.name}"
  default_cooldown     = 60
  min_size             = 2
  max_size             = 5
  desired_capacity     = 2
  vpc_zone_identifier  = ["${aws_subnet.csye6225_a4_Subnet1.id}", "${aws_subnet.csye6225_a4_Subnet3.id}"]
  target_group_arns    = ["${aws_lb_target_group.lb-target-group.arn}"]

  lifecycle {
    create_before_destroy = true
  }
  tag {
    key                 = "Name"
    value               = "csye6225Webapp-ec2"
    propagate_at_launch = true
  }
}

# AUTOSCALING POLICIES for EC2 autoscaling group

# Scale up policy 
resource "aws_autoscaling_policy" "WebServerScaleUpPolicy" {
  name                   = "WebServerScaleUpPolicy"
  scaling_adjustment     = 1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 60
  autoscaling_group_name = "${aws_autoscaling_group.asg.name}"
}

# Scale down policy
resource "aws_autoscaling_policy" "WebServerScaleDownPolicy" {
  name                   = "WebServerScaleDownPolicy"
  scaling_adjustment     = -1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 60
  autoscaling_group_name = "${aws_autoscaling_group.asg.name}"
}

# Scale up when average CPU usage is above 5%. Increment by 1.
resource "aws_cloudwatch_metric_alarm" "CPUAlarmHigh" {
  alarm_name          = "CPUAlarmHigh"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "120"
  statistic           = "Average"
  threshold           = "90"

  dimensions = {
    AutoScalingGroupName = "${aws_autoscaling_group.asg.name}"
  }

  alarm_description = "Scale-up if CPU > 5% for 2 minutes"
  alarm_actions     = ["${aws_autoscaling_policy.WebServerScaleUpPolicy.arn}"]
}

# Scale down when average CPU usage is below 3%. Decrement by 1
resource "aws_cloudwatch_metric_alarm" "CPUAlarmLow" {
  alarm_name          = "CPUAlarmLow"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "120"
  statistic           = "Average"
  threshold           = "3"

  dimensions = {
    AutoScalingGroupName = "${aws_autoscaling_group.asg.name}"
  }

  alarm_description = "Scale-down if CPU < 3% for 2 minutes"
  alarm_actions     = ["${aws_autoscaling_policy.WebServerScaleDownPolicy.arn}"]
}

# Application Load Balancer For Your Web Application
resource "aws_lb" "webapp-lb" {
  name               = "webapp-lb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = ["${aws_security_group.lbSecurityGroup.id}"]
  ip_address_type    = "ipv4"
  enable_deletion_protection = false
  subnets = ["${aws_subnet.csye6225_a4_Subnet1.id}", "${aws_subnet.csye6225_a4_Subnet2.id}"]
  tags = {
    Environment = "production"
  }

}

resource "aws_lb_target_group" "lb-target-group" {
  health_check {
    interval            = 10
    path                = "/"
    protocol            = "HTTP"
    timeout             = 5
    healthy_threshold   = 5
    unhealthy_threshold = 2
  }
  name        = "lb-target-group"
  port        = 8080
  protocol    = "HTTP"
  target_type = "instance"
  vpc_id      = "${aws_vpc.csye6225_a4_vpc.id}"
}

# # EC2 instances launched in the auto-scaling group attached to load balancer.
# resource "aws_autoscaling_attachment" "asg_attachment" {
#   autoscaling_group_name = "${aws_autoscaling_group.asg.id}"
#   elb                    = "${aws_lb.webapp_lb.id}"
# }

#  Application load balancer to accept HTTP traffic on port 80 and forward it to your application instances on whatever port it listens on.
resource "aws_lb_listener" "webapp-lb-listener" {
  load_balancer_arn = "${aws_lb.webapp-lb.arn}"
  port              = "443"
  protocol          = "HTTPS"
  certificate_arn   = "arn:aws:acm:us-east-1:371394122941:certificate/be44f6b1-6fb3-491e-8717-35663500d5bb"

  default_action {
    type             = "forward"
    target_group_arn = "${aws_lb_target_group.lb-target-group.arn}"
  }
}

#Resources to import prod DNS hosted zone
resource "aws_route53_zone" "prodZone" {
  name = "prod.arundathipatil.me"
}

resource "aws_route53_record" "lbAlias" {
  zone_id = "${aws_route53_zone.prodZone.zone_id}"
  name    = "prod.arundathipatil.me"
  type    = "A"

  alias {
    name                   = "${aws_lb.webapp-lb.dns_name}"
    zone_id                = "${aws_lb.webapp-lb.zone_id}"
    evaluate_target_health = false
  }
}


resource "aws_security_group" "lbSecurityGroup" {
  name        = "lbSecurityGroup"
  description = "Allow TLS inbound traffic"
  vpc_id      = "${aws_vpc.csye6225_a4_vpc.id}"

  ingress {
    description = "TLS from VPC-Https"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["${var.allow-all}"]
  }

  ingress {
    description = "TLS from VPC-HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["${var.allow-all}"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "application"
  }
}

resource "aws_security_group_rule" "applicationSecurityGroupRule" {
  type              = "ingress"
  from_port         = 8080
  to_port           = 8080
  protocol          = "tcp"
  security_group_id = "${aws_security_group.application.id}"
  # cidr_blocks = ["0.0.0.0/0"]
  source_security_group_id = "${aws_security_group.lbSecurityGroup.id}"
}

//===========================================================================================================

// Create SNS topic
resource "aws_sns_topic" "password_reset" {
  name = "password-reset"
}


// Creating SQS
resource "aws_sqs_queue" "password_reset_queue" {
  name = "password-reset-queue"
  # visibility_timeout_seconds = 300
  # message_retention_seconds = 86400
  tags = {
    Name = "password-reset-queue"
  }
}

# dead letter queue- for events that cannot be proceesed
# resource "aws_sqs_queue" "password_reset_dl_queue" {
#     name = "password-reset-dl-queue"
# }

resource "aws_sns_topic_subscription" "subscribe_to_sns_topic" {
    topic_arn = "${aws_sns_topic.password_reset.arn}"
    protocol  = "lambda"
    endpoint  = "${aws_lambda_function.emailOnSNS.arn}"
}


# SQS policy that is needed for our SQS to actually receive events from the SNS topic
resource "aws_sqs_queue_policy" "password_reset_queue_policy" {
    queue_url = "${aws_sqs_queue.password_reset_queue.id}"

    policy = <<POLICY
{
  "Version": "2012-10-17",
  "Id": "sqspolicy",
  "Statement": [
    {
      "Sid": "First",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "sqs:SendMessage",
      "Resource": "${aws_sqs_queue.password_reset_queue.arn}",
      "Condition": {
        "ArnEquals": {
          "aws:SourceArn": "${aws_sns_topic.password_reset.arn}"
        }
      }
    }
  ]
}
POLICY
}

# compress the file(s) so that Terraform can then deploy them correctly
# data "archive_file" "lambda_zip" {
#   type        = "zip"
#   source_file =  file("~/deaProjects/git-projects/A9/infrastructure/com/serverless/faas/events")
#   # "${path.module}/lambda/example.js"
#   output_path = 
#   # "${path.module}/lambda/example.zip"
# }




// Create IAM role for  lambda function
resource "aws_iam_role" "iamRoleForlambda" {
  name = "iamRoleForlambda"
  assume_role_policy = data.aws_iam_policy_document.lambda-assume-role-policy.json
#   assume_role_policy = <<EOF
# {
#   "Version": "2012-10-17",
#   "Statement": [
#     {
#       "Action": "sts:AssumeRole",
#       "Principal": {
#         "Service": "lambda.amazonaws.com"
#       },
#       "Effect": "Allow",
#       "Sid": ""
#     }
#   ]
# }
# EOF
}

#assume_role_policy JSON data for Lambda Functions 
data "aws_iam_policy_document" "lambda-assume-role-policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

# Create Lambda function
resource "aws_lambda_function" "emailOnSNS" {
  role          = "${aws_iam_role.iamRoleForlambda.arn}"
  filename         = "${var.lambda_payload_filename}"
  function_name    = "emailOnSNS"
  runtime          = "${var.lambda_runtime}"
  handler          = "${var.lambda_function_handler}"
  memory_size      = 2400
  timeout          = 120
  environment {
    variables = {
      SendersEmail = var.SendersEmail
    }
  }
}

resource "aws_iam_role_policy_attachment" "SNSAccessToEC2Role" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonSNSFullAccess"
  role = "${aws_iam_role.EC2ServiceRole.name}"
}

resource "aws_iam_role_policy_attachment" "SQSAccessToEC2Role" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonSQSFullAccess"
  role = "${aws_iam_role.EC2ServiceRole.name}"
}

resource "aws_iam_role_policy_attachment" "DynamoDbAccessToLambdaFunctionRole" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess"
  role = "${aws_iam_role.iamRoleForlambda.name}"
}

resource "aws_iam_role_policy_attachment" "S3AccessToLambdaFunctionRole" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
  role = "${aws_iam_role.iamRoleForlambda.name}"
}

resource "aws_iam_role_policy_attachment" "SESAccessToLambdaFunctionRole" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonSESFullAccess"
  role = "${aws_iam_role.iamRoleForlambda.name}"
}

resource "aws_iam_role_policy_attachment" "SNSAccessToLambdaFunctionRole" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonSNSFullAccess"
  role = "${aws_iam_role.iamRoleForlambda.name}"
}

resource "aws_iam_role_policy_attachment" "SQSAccessToLambdaFunctionRole" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonSQSFullAccess"
  role = "${aws_iam_role.iamRoleForlambda.name}"
}

resource "aws_iam_role_policy_attachment" "BasicExecutionAccessToLambdaFunctionRole" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
  role = "${aws_iam_role.iamRoleForlambda.name}"
}

resource "aws_iam_policy" "circleci-lambda-update-policy" {
  name        = "circleci-lambda-update-policy"
  description = "Allows cicd user to access lambda function"

   policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "cloudformation:DescribeChangeSet",
                "cloudformation:DescribeStackResources",
                "cloudformation:DescribeStacks",
                "cloudformation:GetTemplate",
                "cloudformation:ListStackResources",
                "cloudwatch:*",
                "cognito-identity:ListIdentityPools",
                "cognito-sync:GetCognitoEvents",
                "cognito-sync:SetCognitoEvents",
                "dynamodb:*",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeSubnets",
                "ec2:DescribeVpcs",
                "events:*",
                "iam:GetPolicy",
                "iam:GetPolicyVersion",
                "iam:GetRole",
                "iam:GetRolePolicy",
                "iam:ListAttachedRolePolicies",
                "iam:ListRolePolicies",
                "iam:ListRoles",
                "iam:PassRole",
                "iot:AttachPrincipalPolicy",
                "iot:AttachThingPrincipal",
                "iot:CreateKeysAndCertificate",
                "iot:CreatePolicy",
                "iot:CreateThing",
                "iot:CreateTopicRule",
                "iot:DescribeEndpoint",
                "iot:GetTopicRule",
                "iot:ListPolicies",
                "iot:ListThings",
                "iot:ListTopicRules",
                "iot:ReplaceTopicRule",
                "kinesis:DescribeStream",
                "kinesis:ListStreams",
                "kinesis:PutRecord",
                "kms:ListAliases",
                "lambda:*",
                "logs:*",
                "s3:*",
                "sns:ListSubscriptions",
                "sns:ListSubscriptionsByTopic",
                "sns:ListTopics",
                "sns:Publish",
                "sns:Subscribe",
                "sns:Unsubscribe",
                "sqs:ListQueues",
                "sqs:SendMessage",
                "tag:GetResources",
                "xray:PutTelemetryRecords",
                "xray:PutTraceSegments"
            ],
            "Resource": "*"
        }
    ]
}
EOF
}
// Attaching circleci-lamba-update-policy to cicd user
resource "aws_iam_user_policy_attachment" "circleci-attach-lambda-update-Policy" {
  user       = "${aws_iam_user.cicd.name}"
  policy_arn = "${aws_iam_policy.circleci-lambda-update-policy.arn}"
}


resource "aws_lambda_permission" "allow_sns" {
  # statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:*"
  function_name = "${aws_lambda_function.emailOnSNS.function_name}"
  principal     = "sns.amazonaws.com"
  source_arn    = "arn:aws:sns:us-east-1:371394122941:password-reset"
}

# resource "aws_lambda_event_source_mapping" "sqstriggerToLambda" {
#   event_source_arn = "${aws_sqs_queue.password_reset_queue.arn}"
#   function_name    = "${aws_lambda_function.emailOnSNS.arn}"
# }
