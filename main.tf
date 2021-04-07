##################
### VARIABLES  ###
##################

variable "profile" {
  type        = string
  description = "The AWS profile configured on the CLI. If no profile was set up in the CLI leave it as default"
}

variable "bucket_name" {
  type        = string
  description = "The name of the bucket that will be used as backend for Vault"
}

variable "vpc_id" {
  type        = string
  description = "The VPC id in which Vault resources should be provided"
}

##################
### PROVIDERS  ###
##################

terraform {
  backend "remote" {
    hostname     = "app.terraform.io"
    organization = "coffee-personal-tf"

    workspaces {
      name = "vault-terraform"
    }
  }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.27"
    }
  }
}

provider "aws" {
  # profile = "personal"
  profile = var.profile
  region  = "us-east-1"
}

############
### IAM  ###
############

resource "aws_iam_policy" "kms_management_access" {
  name = "KMSManagementAccess"
  path = "/"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:DescribeKey",
      ]
      Effect   = "Allow"
      Resource = "*"
    }]
  })

  tags = {
    Name = "KMS Management Access Policy"
    # Description = "Policy that allows KMS Keys encryption, decription and describing"
    Project   = "Vault"
    Terraform = "true"
  }
}

resource "aws_iam_role" "vault_task_role" {
  name        = "VaultTaskRole"
  description = "Allows Vault task to call necessaries AWS services in order to start"
  path        = "/"

  managed_policy_arns = [
    aws_iam_policy.kms_management_access.arn,
    "arn:aws:iam::aws:policy/AmazonS3FullAccess",
    "arn:aws:iam::aws:policy/AmazonSSMReadOnlyAccess",
    "arn:aws:iam::aws:policy/CloudWatchLogsFullAccess",
  ]

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = ""
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ecs-tasks.amazonaws.com"
      }
    }]
  })

  tags = {
    Name        = "Vault Task Role"
    Description = "Allows Vault task to call necessaries AWS services in order to start"
    Project     = "Vault"
    Terraform   = "true"
  }
}

resource "aws_iam_role" "ecs_instance_role" {
  name        = "ecsInstanceRole"
  description = "Allows ECS instances to register to containers"
  path        = "/"

  managed_policy_arns = ["arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role"]

  assume_role_policy = jsonencode({
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Sid = ""
      },
    ]
    Version = "2008-10-17"
  })


  tags = {
    Name        = "ECS Instance Role"
    Description = "Allows ECS instances to register to containers"
    Terraform   = "true"
  }
}

resource "aws_iam_instance_profile" "ecs_instance_profile" {
  name = "ecsInstanceProfile"
  role = aws_iam_role.ecs_instance_role.name

  tags = {
    Name        = "ECS Instance Profile"
    Description = "Allows ECS instances to register to containers"
    Terraform   = "true"
  }
}

#################
### S3 BUCKET ###
#################

resource "aws_s3_bucket" "vault_coffee" {
  bucket = var.bucket_name
  acl    = "private"

  tags = {
    Name        = "Vault Bucket"
    Description = "Vaults backend S3 Bucket"
    Project     = "Vault"
    Terraform   = "true"
  }

  versioning {
    enabled    = true
    mfa_delete = false
  }
}

###############
### KMS KEY ###
###############

resource "aws_kms_key" "vault_key" {
  description = "Vault KMS key for Auto Unseal"

  tags = {
    Name        = "Vault KMS Key"
    Description = "Vault KMS key for Auto Unseal"
    Project     = "Vault"
    Terraform   = "true"
  }
}

######################
### SSM PARAMETERS ###
######################

resource "aws_ssm_parameter" "vault_aws_region" {
  name        = "/vault/AWS_REGION"
  description = "Vault task definition environment variable for AWS_REGION"
  type        = "String"
  value       = "us-east-1"

  tags = {
    Name        = "SSM Parameter /vault/AWS_REGION"
    Description = "Vault task definition environment variable for AWS_REGION"
    Project     = "Vault"
    Terraform   = "true"
  }
}

resource "aws_ssm_parameter" "vault_aws_s3_bucket" {
  name        = "/vault/AWS_S3_BUCKET"
  description = "Vault task definition environment variable for AWS_S3_BUCKET"
  type        = "String"
  value       = aws_s3_bucket.vault_coffee.bucket

  tags = {
    Name        = "SSM Parameter /vault/AWS_S3_BUCKET"
    Description = "Vault task definition environment variable for AWS_S3_BUCKET"
    Project     = "Vault"
    Terraform   = "true"
  }
}

resource "aws_ssm_parameter" "vault_skip_setcap" {
  name        = "/vault/SKIP_SETCAP"
  description = "Vault task definition environment variable for SKIP_SETCAP"
  type        = "String"
  value       = "true"

  tags = {
    Name        = "SSM Parameter /vault/SKIP_SETCAP"
    Description = "Vault task definition environment variable for SKIP_SETCAP"
    Project     = "Vault"
    Terraform   = "true"
  }
}

resource "aws_ssm_parameter" "vault_vault_addr" {
  name        = "/vault/VAULT_ADDR"
  description = "Vault task definition environment variable for VAULT_ADDR"
  type        = "String"
  value       = "http://127.0.0.1:8200"

  tags = {
    Name        = "SSM Parameter /vault/VAULT_ADDR"
    Description = "Vault task definition environment variable for VAULT_ADDR"
    Project     = "Vault"
    Terraform   = "true"
  }
}

resource "aws_ssm_parameter" "vault_vault_awskms_seal_key_id" {
  name        = "/vault/VAULT_AWSKMS_SEAL_KEY_ID"
  description = "Vault task definition environment variable for VAULT_AWSKMS_SEAL_KEY_ID"
  type        = "String"
  value       = aws_kms_key.vault_key.id

  tags = {
    Name        = "SSM Parameter /vault/VAULT_AWSKMS_SEAL_KEY_ID"
    description = "Vault task definition environment variable for VAULT_AWSKMS_SEAL_KEY_ID"
    Project     = "Vault"
    Terraform   = "true"
  }
}

resource "aws_ssm_parameter" "vault_vault_local_config" {
  name        = "/vault/VAULT_LOCAL_CONFIG"
  description = "Vault task definition environment variable for VAULT_LOCAL_CONFIG"
  type        = "String"
  value       = "{\"ui\":true,\"backend\":{\"s3\":{}},\"seal\":{\"awskms\":{}},\"listener\":{\"tcp\":{\"address\":\"0.0.0.0:8200\",\"tls_disable\":1}}}"

  tags = {
    Name        = "SSM Parameter /vault/VAULT_LOCAL_CONFIG"
    Description = "Vault task definition environment variable for VAULT_LOCAL_CONFIG"
    Project     = "Vault"
    Terraform   = "true"
  }
}

resource "aws_ssm_parameter" "vault_vault_seal_type" {
  name        = "/vault/VAULT_SEAL_TYPE"
  description = "Vault task definition environment variable for VAULT_SEAL_TYPE"
  type        = "String"
  value       = "awskms"

  tags = {
    Name        = "SSM Parameter /vault/VAULT_SEAL_TYPE"
    Description = "Vault task definition environment variable for VAULT_SEAL_TYPE"
    Project     = "Vault"
    Terraform   = "true"
  }
}


#######################
### SECURITY GROUPS ###
#######################

resource "aws_security_group" "vault_instance" {
  name        = "Vault Instance"
  description = "Vault Instance Security Group rules"

  ingress = [
    {
      description      = "SSH"
      from_port        = 22
      to_port          = 22
      protocol         = "tcp"
      cidr_blocks      = ["0.0.0.0/0"]
      self             = false
      security_groups  = []
      prefix_list_ids  = []
      ipv6_cidr_blocks = []
    },
    {
      description      = "Vault UI"
      from_port        = 80
      to_port          = 80
      protocol         = "tcp"
      cidr_blocks      = ["0.0.0.0/0"]
      self             = false
      security_groups  = []
      prefix_list_ids  = []
      ipv6_cidr_blocks = []
    },
  ]

  egress = [{
    description      = "Default"
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    self             = false
    security_groups  = []
    prefix_list_ids  = []
    ipv6_cidr_blocks = []
  }]

  tags = {
    Name        = "Vault Instance SG"
    Description = "Vault Instance Security Group rules"
    Project     = "Vault"
    Terraform   = "true"
  }
}

####################
### TARGET GROUP ###
####################

# resource "aws_lb_target_group" "vault" {
#   name     = "vault-tg-tf"
#   protocol = "HTTP"
#   port     = 80
#   vpc_id   = var.vpc_id

#   health_check {
#     path    = "/v1/sys/health"
#     matcher = "200,429,473"
#   }
# }

#######################
### TASK DEFINITION ###
#######################

resource "aws_ecs_task_definition" "vault" {
  family                   = "vault"
  network_mode             = "bridge"
  task_role_arn            = aws_iam_role.vault_task_role.arn
  execution_role_arn       = aws_iam_role.vault_task_role.arn
  requires_compatibilities = ["EC2"]

  tags = {
    Name        = "Vault Task Definition"
    Description = "Vaults tasks execution configuration"
    Project     = "Vault"
    Terraform   = "true"
  }

  container_definitions = jsonencode([{
    name              = "vault"
    image             = "vault:latest"
    essential         = true
    cpu               = 256
    memory            = 512
    memoryReservation = 256
    mountPoints       = []
    environment       = []
    command = [
      "vault",
      "server",
      "-config=/vault/config/local.json",
    ]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = "/ecs/vault"
        awslogs-region        = "us-east-1"
        awslogs-stream-prefix = "ecs"
      }
    }
    volumesFrom = []
    portMappings = [
      {
        hostPort      = 80
        containerPort = 8200
        protocol      = "tcp"
      },
    ]
    secrets = [
      {
        name      = "AWS_REGION"
        valueFrom = aws_ssm_parameter.vault_aws_region.arn
      },
      {
        name      = "AWS_S3_BUCKET"
        valueFrom = aws_ssm_parameter.vault_aws_s3_bucket.arn
      },
      {
        name      = "SKIP_SETCAP"
        valueFrom = aws_ssm_parameter.vault_skip_setcap.arn
      },
      {
        name      = "VAULT_ADDR"
        valueFrom = aws_ssm_parameter.vault_vault_addr.arn
      },
      {
        name      = "VAULT_AWSKMS_SEAL_KEY_ID"
        valueFrom = aws_ssm_parameter.vault_vault_awskms_seal_key_id.arn
      },
      {
        name      = "VAULT_LOCAL_CONFIG"
        valueFrom = aws_ssm_parameter.vault_vault_local_config.arn
      },
      {
        name      = "VAULT_SEAL_TYPE"
        valueFrom = aws_ssm_parameter.vault_vault_seal_type.arn
      },
    ]
  }])
}

###############
### CLUSTER ###
###############

resource "aws_ecs_cluster" "vault" {
  name = "Vault"

  tags = {
    Name        = "Vault Cluster"
    Description = "Vault ECS Cluster"
    Project     = "Vault"
    Terraform   = "true"
  }
}

###############
### SERVICE ###
###############

resource "aws_ecs_service" "vault" {
  name            = "Vault"
  cluster         = aws_ecs_cluster.vault.id
  task_definition = aws_ecs_task_definition.vault.arn
  desired_count   = 1

  ordered_placement_strategy {
    type  = "binpack"
    field = "cpu"
  }

  # load_balancer {
  #   target_group_arn = aws_lb_target_group.vault.arn
  #   container_name   = "vault"
  #   container_port   = 8200
  # }

  # placement_constraints {
  #   type       = "memberOf"
  #   expression = "attribute:ecs.availability-zone in [us-west-2a, us-west-2b]"
  # }

  tags = {
    Name        = "Vault Service"
    Description = "Vault ECS Service"
    Project     = "Vault"
    Terraform   = "true"
  }
}

##########################
### SPOT FLEET REQUEST ###
##########################

data "template_file" "vault_instance_user_data" {
  template = <<EOF
    #!/bin/bash
    echo "ECS_CLUSTER=${aws_ecs_cluster.vault.name}" >> /etc/ecs/ecs.config
  EOF
}

resource "aws_launch_template" "vault" {
  name          = "Vault"
  image_id      = "ami-005425225a11a4777"
  instance_type = "t3.micro"
  key_name      = "vault"
  user_data     = base64encode(data.template_file.vault_instance_user_data.rendered)

  placement {
    tenancy = "default"
  }

  iam_instance_profile {
    arn = aws_iam_instance_profile.ecs_instance_profile.arn
  }

  block_device_mappings {
    device_name = "/dev/sda1"
    ebs {
      delete_on_termination = true
      volume_size           = 30
      volume_type           = "gp2"
    }
  }

  network_interfaces {
    description                 = "Vault spot instance network interface"
    device_index                = 0
    delete_on_termination       = true
    associate_public_ip_address = true
    security_groups             = [aws_security_group.vault_instance.id]
  }

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name        = "Vault"
      Description = "Vault spot fleet request's instance"
      Project     = "Vault"
      Terraform   = "true"
    }
  }

  tags = {
    Name        = "Vault"
    Description = "Vault instance launch template"
    Project     = "Vault"
    Terraform   = "true"
  }
}

resource "aws_spot_fleet_request" "vault" {
  lifecycle {
    create_before_destroy = true
  }

  instance_pools_to_use_count         = 1
  target_capacity                     = 1
  terminate_instances_with_expiration = false
  allocation_strategy                 = "lowestPrice"
  excess_capacity_termination_policy  = "Default"
  valid_until                         = "2999-11-04T20:44:20Z"
  iam_fleet_role                      = "arn:aws:iam::277048801940:role/aws-ec2-spot-fleet-tagging-role"

  tags = {
    "Name"        = "Vault"
    "Description" = "Vault spot fleet request"
    "Project"     = "Vault"
    "Terraform"   = "true"
  }

  launch_template_config {
    launch_template_specification {
      id      = aws_launch_template.vault.id
      version = aws_launch_template.vault.latest_version
    }

    overrides {
      instance_type = "t3.micro"
    }

    overrides {
      instance_type = "t3a.micro"
    }

    overrides {
      instance_type = "t2.micro"
    }
  }
}
