#!/bin/bash
set -euxo pipefail

# Docker to run the target and the test JDK; tmux/python3 for the demo.
dnf install -y docker tmux python3
systemctl enable --now docker
usermod -aG docker ec2-user

# Mark the instance as a lab machine.
echo "j4s-lab $(date -Is)" > /etc/j4s-lab
