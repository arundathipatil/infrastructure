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

  ingress {
    description = "TLS from VPC-Https"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.csye6225_a4_vpc.cidr_block]
  }

  ingress {
    description = "TLS from VPC-HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.csye6225_a4_vpc.cidr_block]
  }

  ingress {
    description = "TLS from VPC-Custom TCP"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.csye6225_a4_vpc.cidr_block]
  }

  ingress {
    description = "TLS from VPC-SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.csye6225_a4_vpc.cidr_block]
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


resource "aws_security_group" "database" {
  name        = "database"
  description = "Allow TLS inbound traffic"
  vpc_id      = "${aws_vpc.csye6225_a4_vpc.id}"

  ingress {
    description = "TLS from VPC-mysql"
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.csye6225_a4_vpc.cidr_block]
  }
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
  source_security_group_id = "${aws_security_group.application.id}"
}

resource "aws_kms_key" "mykey" {
  description             = "This key is used to encrypt bucket objects"
  # deletion_window_in_days = 30
}

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
  parameter_group_name = "default.mysql5.7"
  engine               = "mysql"
  instance_class       = "db.t3.micro"
  multi_az             = false 
  identifier           = "csye6225-su2020"
  username             = "csye6225su2020"
  password             = "foobarbaz"
  db_subnet_group_name = "${aws_db_subnet_group.dbSubnetGroup.name}"
  publicly_accessible  = false
  name                 = "csye6225"
  vpc_security_group_ids = ["${aws_security_group.database.id}"]
  skip_final_snapshot     = true
}

resource "aws_instance" "csye6225Webapp" {
  ami           = "${var.amiId}"
  instance_type = "t2.micro"
  disable_api_termination  = false
  subnet_id = "${aws_subnet.csye6225_a4_Subnet1.id}"

   root_block_device {
    volume_size           = "${var.EC2_ROOT_VOLUME_SIZE}"
    volume_type           = "${var.EC2_ROOT_VOLUME_TYPE}"
    delete_on_termination = "${var.EC2_ROOT_VOLUME_DELETE_ON_TERMINATION}"
  }
  vpc_security_group_ids = ["${aws_security_group.application.id}"]
  tags = {
    Name = "csye6225Webapp"
  }
}