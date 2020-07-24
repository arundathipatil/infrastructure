variable "access_key_id" {
    #  default = ""
}
variable "secret_key_id" {
    #  default = ""
}

variable "aws_region" {
	# default = "us-east-1"
}

variable "vpc_cidr" {
	default = "10.0.0.0/16"
}

variable "subnet1_cidr" {
	default = "10.0.0.0/24"
}

variable "subnet2_cidr" {
	default = "10.0.1.0/24"
}

variable "subnet3_cidr" {
	default = "10.0.2.0/24"
}

variable "routeTable_cidr" {
	default = "0.0.0.0/0"
}

variable "availabilityZone1" {
    #  default = "us-east-1a"
}
variable "availabilityZone2" {
    #  default = "us-east-1b"
}
variable "availabilityZone3" {
    #  default = "us-east-1c"
}

variable "amiId" {

}

variable "EC2_ROOT_VOLUME_SIZE" {
	default = 20
}

variable "EC2_ROOT_VOLUME_TYPE" {
	default = "gp2"
}

variable "EC2_ROOT_VOLUME_DELETE_ON_TERMINATION" {
	default = true
}

variable allow-all {
	default = "0.0.0.0/0"
}

variable database_username {
	default = "csye6225su2020"
}

variable database_password {
	default = "foobarbaz"
}

variable "lambda_payload_filename" {
  default = "~/faas/faas-0.0.1-SNAPSHOT.jar"
}

variable "lambda_runtime" {
  default = "java8"
}

variable "lambda_function_handler" {
  default = "com.serverless.faas.events.EmailEvent::handleRequest"
}

variable "SendersEmail" {
  default = "donotreply@prod.arundathipatil.me"
}