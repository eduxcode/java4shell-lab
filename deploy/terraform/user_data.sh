#!/bin/bash
set -euxo pipefail

# Docker para rodar o alvo e o JDK de teste; tmux/python3 para a demo.
dnf install -y docker tmux python3
systemctl enable --now docker
usermod -aG docker ec2-user

# Marca a instancia como laboratorio.
echo "j4s-lab $(date -Is)" > /etc/j4s-lab
