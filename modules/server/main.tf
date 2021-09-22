resource "aws_s3_bucket" "vault" {
  bucket = var.vault_bucket_name
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

resource "aws_kms_key" "vault_key" {
  description = "Vault KMS key for Auto Unseal"

  tags = {
    Name        = "Vault KMS Key"
    Description = "Vault KMS key for Auto Unseal"
    Project     = "Vault"
    Terraform   = "true"
  }
}

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
  value       = aws_s3_bucket.vault.bucket

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
  value = jsonencode({
    ui                = true,
    backend           = { s3 = {} },
    seal              = { awskms = {} },
    default_lease_ttl = "168h",
    max_lease_ttl     = "720h",
    listener = {
      tcp = {
        address     = "0.0.0.0:8200",
        tls_disable = 1
      }
    }
  })

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

resource "aws_ssm_parameter" "vault_disable_mlock" {
  name        = "/vault/VAULT_DISABLE_MLOCK"
  description = "Vault task definition environment variable for VAULT_DISABLE_MLOCK"
  type        = "String"
  value       = "true"

  tags = {
    Name        = "SSM Parameter /vault/VAULT_DISABLE_MLOCK"
    Description = "Vault task definition environment variable for VAULT_DISABLE_MLOCK"
    Project     = "Vault"
    Terraform   = "true"
  }
}

resource "aws_iam_policy" "kms_management_access" {
  name = "KMSManagementAccessPolicy"
  policy = jsonencode(
    {
      Statement = [
        {
          Action = [
            "kms:Decrypt",
            "kms:Encrypt",
            "kms:DescribeKey",
          ]
          Effect   = "Allow"
          Resource = "*"
          Sid      = "VisualEditor0"
        },
      ]
      Version = "2012-10-17"
    }
  )

  tags = {
    Name        = "KMS Management Access Policy"
    Description = "Policy that allows KMS Keys encryption decription and describing"
    Project     = "Vault"
    Terraform   = "true"
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

resource "aws_cloudwatch_log_group" "vault" {
  name              = "/ecs/vault"
  retention_in_days = 30

  tags = {
    Name        = "Vault log group"
    Description = "Cloudwatch log group for Vault containers"
    Project     = "Vault"
    Terraform   = "true"
  }
}

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
    privileged        = true
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
      {
        name      = "VAULT_DISABLE_MLOCK"
        valueFrom = aws_ssm_parameter.vault_disable_mlock.arn
      },
    ]
  }])
}

resource "aws_ecs_cluster" "vault" {
  name = "Vault"

  tags = {
    Name        = "Vault Cluster"
    Description = "Vault ECS Cluster"
    Project     = "Vault"
    Terraform   = "true"
  }
}

resource "aws_ecs_service" "vault" {
  name            = "Vault"
  cluster         = aws_ecs_cluster.vault.id
  task_definition = aws_ecs_task_definition.vault.arn
  desired_count   = 1

  ordered_placement_strategy {
    field = "instanceId"
    type  = "spread"
  }

  ordered_placement_strategy {
    field = "attribute:ecs.availability-zone"
    type  = "spread"
  }

  tags = {
    Name        = "Vault Service"
    Description = "Vault ECS Service"
    Project     = "Vault"
    Terraform   = "true"
  }
}

data "aws_ami" "ecs_ami" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn-ami-*-amazon-ecs-optimized"]
  }
}

resource "tls_private_key" "vault" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "vault" {
  key_name   = "vault"
  public_key = tls_private_key.vault.public_key_openssh

  tags = {
    Name        = "Vault public key"
    Description = "Vault Instance OpenSSH public key"
    Project     = "Vault"
    Terraform   = "true"
  }
}

data "template_file" "vault_instance_user_data" {
  template = <<EOF
    #!/bin/bash
    echo "ECS_CLUSTER=${aws_ecs_cluster.vault.name}" >> /etc/ecs/ecs.config
  EOF
}

resource "aws_iam_role" "ecs_instance_role" {
  name        = "EcsInstanceRole"
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
    Description = "Allows EC2 instances to be used as an ECS Cluster"
    Terraform   = "true"
  }
}

resource "aws_iam_instance_profile" "ecs_instance_profile" {
  name = "EcsInstanceProfile"
  role = aws_iam_role.ecs_instance_role.name

  tags = {
    Name        = "ECS Instance Profile"
    Description = "Allows EC2 instances to be used as an ECS Cluster"
    Terraform   = "true"
  }
}

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
      description      = "SSH"
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

resource "aws_launch_template" "vault" {
  name          = "Vault"
  image_id      = data.aws_ami.ecs_ami.image_id
  instance_type = var.instance_types[0]
  key_name      = aws_key_pair.vault.key_name
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

data "aws_caller_identity" "current" {}

locals {
  account_id  = data.aws_caller_identity.current.account_id
  account_arn = data.aws_caller_identity.current.arn
}

resource "aws_spot_fleet_request" "vault" {
  instance_pools_to_use_count         = 1
  target_capacity                     = 1
  terminate_instances_with_expiration = false
  allocation_strategy                 = "lowestPrice"
  excess_capacity_termination_policy  = "Default"
  valid_until                         = "2999-11-04T20:44:20Z"
  iam_fleet_role                      = "arn:aws:iam::${local.account_id}:role/aws-ec2-spot-fleet-tagging-role"

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

    dynamic "overrides" {
      for_each = var.instance_types
      content {
        instance_type = overrides.value
      }
    }
  }
}
