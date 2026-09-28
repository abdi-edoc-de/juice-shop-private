# vuln-code-snippet start iacLeakedKeyChallenge
data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "${var.project_name}-vpc"
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_subnet" "public" {
  count                   = length(var.public_subnet_cidrs)
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_subnet_cidrs[count.index]
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name        = "${var.project_name}-public-${count.index}"
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name        = "${var.project_name}-igw"
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = {
    Name        = "${var.project_name}-public-rt"
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_route_table_association" "public" {
  count          = length(var.public_subnet_cidrs)
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_security_group" "alb" {
  name        = "${var.project_name}-alb-sg"
  description = "Security group for ALB"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${var.project_name}-alb-sg"
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_security_group" "ecs" {
  name        = "${var.project_name}-ecs-sg"
  description = "Security group for ECS tasks"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 3000
    to_port         = 3000
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${var.project_name}-ecs-sg"
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_lb" "juice_shop" {
  name               = "${var.project_name}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = aws_subnet.public[*].id

  tags = {
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_lb_target_group" "juice_shop" {
  name        = "${var.project_name}-tg"
  port        = 3000
  protocol    = "HTTP"
  vpc_id      = aws_vpc.main.id
  target_type = "ip"

  health_check {
    path                = "/rest/admin/application-version"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    timeout             = 5
    interval            = 30
    matcher             = "200"
  }

  tags = {
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.juice_shop.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.juice_shop.arn
  }
}

resource "aws_iam_server_certificate" "juice_shop_tls" {
  name             = "${var.project_name}-tls-cert"
  certificate_body = file("${path.module}/certs/server.crt")
  private_key      = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAsxeFgtDMxP8+RB+rdYlPuQD1gdLkIPE6LNX7lfTkvVk6IaBS\nrZSaSdbzubHZAgMr2QLkmHRPffHziOlj+HCBWwzGbkv9Wl2AwIEgxsksGooRwMER\nL/TxMO8252opWoWam3S5zK/cApecDxkxIqsEA4QkKc5lizAy3bhZEc3OXnOY+N1c\nV4H93Y0eczyn9PzzalFQzZxGx4erirg/lBOz18PjjWMVas5nEZgb3/CPLrTm938Z\nddN3XSn8BiKYrClFdtHTw9ZvRVKLOWxUF+ec6oT7tk6UWZvq6JpItz/2qfMAxFFY\nZo1E7xWQ72L88mwY/6SwRv8nzBWcKHvOY+d9ywIDAQABAoIBADDFLAeGwuy2sYct\ntKyKWxp/Z1wWSSeraXNCRoP8r7ncrZbwqPM6L5YCIlckVntUz8EGJ6hYrDkZBX/4\nRtAmGyPnY7YvnWvZYLGLuJhJumfzx4fdS8fqhTAVRLdaUq6jCYpiDCLwlRJjpQz7\niETvm2U1u/9ihIaV9pQomqDdkeBoVhVSqvlD6FoYv8JKppt6zE33ea3ZPmcIOGUE\nYR4SQk0/nFrZ79AIPcD+7ZbqXaU9gULXLwisz0nJDigPISjRM8B55OfGw9f0q3bS\nhsr63QdNMWeg0Mu0Zk+JvzGkP/aJNYk7f6XhCCL0sOGDqkM+yniLrQiExXC227KN\nE3xAw2kCgYEA/p4E2a2Gqh2YLOrGM8UFJpXbBcSIRn1XY5ZaNYNpxNW7YdTWRpIg\nkSH9CyxqgGip1WQRrf0YES0ihFn8qsWaz5JEScC0XOSQhHl9E6loDdmfE5R+hRll\nW+q8lWiTd1VAjItcfhVYNchRy95yAVdmUCWG4roWP28140l/8oKcxZ8CgYEAtBCA\n67izVuB1jiCl8uMp4O3wwRGdL1lXZ+GYFpEU4NQiGjT3jDCJQtytDwoiX0dTK2Px\nISvDebc/G/f7R/CI6l8zTxdZRgVZgkZEhNE4OaxFTK/nFxbxNFK9UK+MPjnQTZoJ\ngpU/A4hoZmCk2OiJoC545PFkssByW0FYSsUaIFUCgYEAz5CeP54Yc8Hgdm2F2lo4\n0rXDcTZAKcawYP0G2S0iIlZihWRuseUaK3ZbxKoWwEuSd+U2DHKRFh+HTgHV2plw\nlNqWVNGFt1yU+4nWjxrBOtk3t0yMv5BucrovtlUkMloLXweVBSv9VwrQs7PJmJJZ\nU+jjxx0QWfIdKgaXCWm0x90CgYAnKnvQSgGAQRxwyLsv5KdkTH0Uka898FHpv5Ek\nP3RqHto4FxNNQ/VnPLbL0al+TfZSNs/pJirDm883Vy4qDLDLQd/YMTzy1REOHBil\nRxjSupzsPEqopA3dEq4pEbYQhuS/LGUrKSlmrFIBCr5wi8v7soALVFJR6zg0jzcU\nNGElbQKBgAgNJWZEpiplS6E6XciayCFZdt93XAxfVJDacz7Mk0n8pFyFRJvFhRfr\nCInqcyixnIo/vfN+GjxR/599VyxMxz88+E66BZjXjWlpUGC1yONAKA9TVRieNjN2\naUdopUE6uzbcVQ7SSGM7G3RVeQNyzMRVZ5w5RkM+O5flMdGGpAJl\n-----END RSA PRIVATE KEY-----" # vuln-code-snippet vuln-line iacLeakedKeyChallenge

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.juice_shop.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_iam_server_certificate.juice_shop_tls.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.juice_shop.arn
  }
}

resource "aws_iam_role" "ecs_execution" {
  name = "${var.project_name}-ecs-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_iam_role_policy_attachment" "ecs_execution" {
  role       = aws_iam_role.ecs_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_security_group" "efs" {
  name        = "${var.project_name}-efs-sg"
  description = "Security group for EFS mount targets"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 2049
    to_port         = 2049
    protocol        = "tcp"
    security_groups = [aws_security_group.ecs.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${var.project_name}-efs-sg"
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_efs_file_system" "juice_shop_data" {
  creation_token = "${var.project_name}-sqlite-data"
  encrypted      = var.efs_encrypted

  performance_mode = "generalPurpose"
  throughput_mode  = "bursting"

  tags = {
    Name        = "${var.project_name}-sqlite-data"
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_efs_mount_target" "juice_shop_data" {
  count           = length(var.public_subnet_cidrs)
  file_system_id  = aws_efs_file_system.juice_shop_data.id
  subnet_id       = aws_subnet.public[count.index].id
  security_groups = [aws_security_group.efs.id]
}

resource "aws_efs_access_point" "juice_shop_data" {
  file_system_id = aws_efs_file_system.juice_shop_data.id

  posix_user {
    uid = 1000
    gid = 1000
  }

  root_directory {
    path = "/data"
    creation_info {
      owner_uid   = 1000
      owner_gid   = 1000
      permissions = "755"
    }
  }

  tags = {
    Name        = "${var.project_name}-data-ap"
    Project     = var.project_name
    Environment = var.environment
  }
}
# vuln-code-snippet end iacLeakedKeyChallenge
