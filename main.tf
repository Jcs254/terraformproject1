terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "4.61.0"
    }

  }
}
provider "aws" {
  region = "us-east-1"
}

resource "aws_vpc" "utc_vpc" {
  cidr_block           = "10.10.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = {
    Name = "utc-vpc"
    env  = "dev"
    team = "config management"
  }
}

resource "aws_subnet" "public_subnet1" {
  vpc_id                  = aws_vpc.utc_vpc.id
  cidr_block              = "10.10.1.0/24"
  availability_zone       = "us-east-1a"
  map_public_ip_on_launch = true
  tags = {
    Name = "public-subnet"
    env  = "dev"
    team = "config management"
  }
}
resource "aws_subnet" "public_subnet2" {
  vpc_id                  = aws_vpc.utc_vpc.id
  cidr_block              = "10.10.2.0/24"
  availability_zone       = "us-east-1b"
  map_public_ip_on_launch = true
  tags = {
    Name = "public-subnet"
    env  = "dev"
    team = "config management"
  }
}
resource "aws_subnet" "public_subnet3" {
  vpc_id                  = aws_vpc.utc_vpc.id
  cidr_block              = "10.10.3.0/24"
  availability_zone       = "us-east-1c"
  map_public_ip_on_launch = true
  tags = {
    Name = "public-subnet"
    env  = "dev"
    team = "config management"
  }
}
resource "aws_subnet" "private_subnet1" {
  availability_zone = "us-east-1a"
  vpc_id            = aws_vpc.utc_vpc.id
  cidr_block        = "10.10.4.0/24"
  tags = {
    Name = "subnet-private-vpc"
    env  = "Dev"
    team = "config management"
  }

}
resource "aws_subnet" "private_subnet2" {
  availability_zone = "us-east-1b"
  vpc_id            = aws_vpc.utc_vpc.id
  cidr_block        = "10.10.5.0/24"
  tags = {
    Name = "subnet-private-vpc"
    env  = "Dev"
    team = "config management"
  }

}
resource "aws_subnet" "private_subnet3" {
  availability_zone = "us-east-1a"
  vpc_id            = aws_vpc.utc_vpc.id
  cidr_block        = "10.10.6.0/24"
  tags = {
    Name = "subnet-private-vpc"
    env  = "Dev"
    team = "config management"
  }

}
resource "aws_subnet" "private_subnet4" {
  availability_zone = "us-east-1b"
  vpc_id            = aws_vpc.utc_vpc.id
  cidr_block        = "10.10.7.0/24"
  tags = {
    Name = "subnet-private-vpc"
    env  = "Dev"
    team = "config management"
  }

}
resource "aws_subnet" "private_subnet5" {
  availability_zone = "us-east-1c"
  vpc_id            = aws_vpc.utc_vpc.id
  cidr_block        = "10.10.8.0/24"
  tags = {
    Name = "subnet-private-vpc"
    env  = "Dev"
    team = "config management"
  }

}
resource "aws_subnet" "private_subnet6" {
  availability_zone = "us-east-1c"
  vpc_id            = aws_vpc.utc_vpc.id
  cidr_block        = "10.10.9.0/24"
  tags = {
    Name = "subnet-private-vpc"
    env  = "Dev"
    team = "config management"
  }

}
resource "aws_internet_gateway" "utc_igw" {
  vpc_id = aws_vpc.utc_vpc.id
  tags = {
    Name = "utc-internet-gateway"
    env  = "dev"
    team = "config management"
  }
}

resource "aws_eip" "ei" {

}
resource "aws_nat_gateway" "nat1" {
  allocation_id = aws_eip.ei.id
  subnet_id     = aws_subnet.public_subnet1.id

  tags = {
    Name = "gw NAT"
  }
  # To ensure proper ordering, it is recommended to add an explicit dependency
  # on the Internet Gateway for the VPC.
  depends_on = [aws_internet_gateway.utc_igw]
}

#resource "aws_nat_gateway" "nat2" {
#allocation_id = "id=nat-01a0753fdabc8b4e7"
#subnet_id     = aws_subnet.public_subnet2.id
#tags = {
#Name = "gw Nat2"

resource "aws_instance" "utc_instance" {
  count                  = 1
  ami                    = "ami-0fa1ca9559f1892ec"
  instance_type          = "t2.micro"
  key_name               = "utc-key"
  subnet_id              = aws_subnet.public_subnet1.id
  vpc_security_group_ids = [aws_security_group.app_server_sg.id]
  tags = {
    Name = "appserver-${element(["1a", "1b"], count.index)}"
    env  = "dev"
    team = "config management"
  }

  user_data = <<-EOF
              #!bin/bash
              yum update -y
              yum install -y httpd.x86_64
              systemctl start httpd.service
              systemctl enable httpd.service
              echo "Hello World from \$(hostname -f)" > /var/www/html/index.html
              EOF
}

#resource "aws_instance" "utc_instance2" {
# ami = "ami-0fa1ca9559f1892ec"  
#instance_type = "t2.micro"
#key_name = "utc-key"
#subnet_id = "aws_subnet.private_subnet2.id"
#vpc_security_group_ids = [aws_security_group.app_server_sg.id]

resource "aws_security_group" "alb_sg" {
  name        = "alb-sg"
  description = "ALB Security Group"
  vpc_id      = aws_vpc.utc_vpc.id

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
    env  = "dev"
    team = "config management"
  }
}
resource "aws_security_group" "bastion_host_sg" {
  name        = "bastion-host-sg"
  description = "Bastion Host Security Group"
  vpc_id      = aws_vpc.utc_vpc.id

  ingress {
    from_port = 22
    to_port   = 22
    protocol  = "tcp"
    #cidr_blocks = var.my_ip/32 # Replace with your IP address
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    env  = "dev"
    team = "config management"
  }
}
resource "aws_security_group" "app_server_sg" {
  name        = "app-server-sg"
  description = "Security group for the application server"
  vpc_id      = aws_vpc.utc_vpc.id

  ingress {
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg.id]
  }

  ingress {
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.bastion_host_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    env  = "dev"
    team = "config management"
  }
}

resource "aws_security_group" "database_sg" {
  name        = "database-sg"
  description = "Database Security Group"
  vpc_id      = aws_vpc.utc_vpc.id

  ingress {
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.app_server_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    env  = "dev"
    team = "config management"
  }
}
#Generates a secure private k ey and encodes it as PEM
resource "tls_private_key" "utc-key" {
  algorithm = "RSA"
  rsa_bits  = 2048
}
# Create the Key Pair
resource "aws_key_pair" "utc-key" {
  key_name   = "utc-key"
  public_key = tls_private_key.utc-key.public_key_openssh
}
# Save file
resource "local_file" "ssh_key" {
  filename = "utc-key.pem"
  content  = tls_private_key.utc-key.private_key_pem
}

resource "aws_instance" "bastion_host" {
  ami                    = "ami-0fa1ca9559f1892ec" # replace with your AMI ID
  instance_type          = "t2.micro"
  key_name               = aws_key_pair.utc-key.key_name
  subnet_id              = aws_subnet.public_subnet1.id 
  vpc_security_group_ids = [aws_security_group.bastion_host_sg.id]
  tags = {
    env  = "dev"
    team = "config managment"
  }
  user_data = <<-EOF
              #!/bin/bash
              # Script to copy key to private server
              aws s3 cp s3://<YOUR_BUCKET>/<PATH_TO_PRIVATE_KEY> /home/ec2-user/.ssh/id_rsa
              chmod 400 /home/ec2-user/.ssh/id_rsa
              EOF


}


#provisioner "file" {
# source      = aws_key_pair.utc-key.public_key
#destination = "/home/ec2-user/.ssh/authorized_keys"


#provisioner "remote-exec" {
#inline = [
# "chmod 400 /home/ec2-user/.ssh/authorized_keys"



resource "aws_lb_target_group" "utc_target_group" {
  name        = "utc-target-group"
  port        = 80
  protocol    = "HTTP"
  vpc_id      = aws_vpc.utc_vpc.id
  target_type = "instance"
  health_check {
    protocol = "HTTP"
    path     = "/"
  }
  tags = {
    env  = "dev"
    team = "config management"
  }
}

resource "aws_lb" "utc_load_balancer" {
  name                             = "utc-load-balancer"
  internal                         = false
  load_balancer_type               = "application"
  security_groups                  = [aws_security_group.alb_sg.id]
  enable_deletion_protection       = false
  enable_cross_zone_load_balancing = true
  subnets                          = ["${aws_subnet.public_subnet1.id}", "${aws_subnet.public_subnet2.id}"]

  enable_http2 = true
  idle_timeout = 60
  #enable_deletion_protection = false

  tags = {
    env  = "dev"
    team = "config management"
  }
}
resource "aws_db_instance" "utc_dev_database" {
  identifier        = "utc-dev-database"
  engine            = "mysql"
  allocated_storage = 20
  storage_type      = "gp2"
  instance_class    = "db.t2.micro"
  #name                 = "utc_dev_database"
  username            = "utcuser"
  password            = "utcdev12345"
  publicly_accessible = false
  
}

resource "aws_iam_role" "ec2_s3_role" {
  name               = "ec2-s3-role"
  assume_role_policy = <<-EOF
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
}
resource "aws_efs_file_system" "efs" {
  creation_token   = "efs"
  performance_mode = "generalPurpose"
  throughput_mode  = "bursting"
  tags = {
    env  = "dev"
    team = "config management"
  }
}

resource "aws_instance" "appserver_1a" {
  count                  = 2
  ami                    = "ami-0fa1ca9559f1892ec" # replace with your AMI ID
  instance_type          = "t2.micro"
  key_name               = aws_key_pair.utc-key.key_name
  subnet_id              = aws_subnet.private_subnet2.id
  vpc_security_group_ids = [aws_security_group.app_server_sg.id]
  user_data              = <<-EOF
                #!/bin/bash
                yum update -y
                yum install -y httpd.x86_64
                systemctl start httpd.service
                systemctl enable httpd.service
                echo "Hello World from \$(hostname -f)" > /var/www/html/index.html
              EOF
  tags = {
    Name = "appserver-1a-${count.index}"
    env  = "dev"
    team = "config management"
  }
}
resource "aws_autoscaling_group" "utc_asg" {
  desired_capacity    = 2
  max_size            = 4
  min_size            = 2
  vpc_zone_identifier = [aws_subnet.private_subnet1.id]
  launch_template {
    id      = aws_launch_template.utc_lt.id
    version = "$Latest"
  }

  health_check_type         = "EC2"
  health_check_grace_period = 300
  force_delete              = true
  wait_for_capacity_timeout = "0"
  protect_from_scale_in     = false

  tag {
    key                 = "team"
    value               = "config management"
    propagate_at_launch = true
  }
}
resource "aws_launch_template" "utc_lt" {
  name = "utc-lt"
  #version       = "$Latest"
  image_id               = "ami-0fa1ca9559f1892ec" # replace with your AMI ID
  instance_type          = "t2.micro"
  key_name               = aws_key_pair.utc-key.key_name
  vpc_security_group_ids = [aws_security_group.app_server_sg.id]
  #user_data = base64encode("#!/bin/bash\n\necho 'Hello, World!' > /tmp/hello.txt")

  #!/bin/bash
  #yum update -y
  #yum install -y httpd.x86_64
  # systemctl start httpd.service
  # systemctl enable httpd.service
  # echo "Hello World from \$(hostname -f)" > /var/www/html/index.html
  #EOF


}
resource "aws_cloudwatch_metric_alarm" "scale_out_cpu" {
  alarm_name          = "scale-out-on-high-cpu"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "300"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "This metric monitors CPU utilization and triggers an alarm when the average CPU utilization is greater than or equal to 80% for 2 periods."
  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.utc_asg.name
  }

  #alarm_actions = [aws_sns_topic.utc_auto]
}

# Task 19 - Create SNS Topic and Subscription
resource "aws_sns_topic" "utc-auto-scaling-topic" {
  name = "utc-auto-scaling"
}

resource "aws_sns_topic_subscription" "config-management-subscription" {
  topic_arn = aws_sns_topic.utc-auto-scaling-topic.arn
  protocol  = "email"
  endpoint  = "<joan_hhi@yahoo.com>"
}