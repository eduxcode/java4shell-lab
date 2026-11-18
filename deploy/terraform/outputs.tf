output "public_ip" {
  value = aws_instance.lab.public_ip
}

output "ssh" {
  value = "ssh -i <sua-chave.pem> ec2-user@${aws_instance.lab.public_ip}"
}

output "lembrete" {
  value = "DESTRUA ao terminar: terraform destroy"
}
