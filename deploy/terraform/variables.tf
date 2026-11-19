variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "instance_type" {
  description = "Requires AVX-512 VBMI: c6i (Ice Lake), c7i/m7i (Sapphire Rapids)"
  type        = string
  default     = "c6i.large"

  validation {
    condition     = can(regex("^(c6i|m6i|c7i|m7i|c7a|m7a)\\.", var.instance_type))
    error_message = "Use a family with AVX-512 VBMI (c6i/m6i/c7i/m7i)."
  }
}

variable "key_name" {
  description = "EC2 key pair name for SSH"
  type        = string
}

variable "allowed_cidr" {
  description = "Your public IP as /32. E.g. 203.0.113.10/32"
  type        = string
}
