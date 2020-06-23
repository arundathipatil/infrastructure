#!/bin/bash
echo "username=csye6225su2020" >> /etc/environment
echo "password=foobarbaz" >> /etc/environment
echo "s3bucketname=webapp.arundathi.patil" >> /etc/environment
echo "ACCESS_KEY=${ACCESS_KEY}" >> /etc/environment
echo "SECRET_KEY=${SECRET_KEY}" >> /etc/environment
echo "rdsinstance=${rds_endpoint}" >> /etc/environment