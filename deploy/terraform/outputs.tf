output "public_ip" {
  value = aws_instance.lab.public_ip
}

output "ssh" {
  value = "ssh -i <your-key.pem> ec2-user@${aws_instance.lab.public_ip}"
}

output "reminder" {
  value = "DESTROY when done: terraform destroy"
}
