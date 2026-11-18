variable "region" {
  description = "Regiao AWS"
  type        = string
  default     = "us-east-1"
}

variable "instance_type" {
  description = "Precisa de AVX-512 VBMI: c6i (Ice Lake), c7i/m7i (Sapphire Rapids)"
  type        = string
  default     = "c6i.large"

  validation {
    condition     = can(regex("^(c6i|m6i|c7i|m7i|c7a|m7a)\\.", var.instance_type))
    error_message = "Use uma familia com AVX-512 VBMI (c6i/m6i/c7i/m7i)."
  }
}

variable "key_name" {
  description = "Nome do key pair EC2 para SSH"
  type        = string
}

variable "allowed_cidr" {
  description = "Seu IP publico em /32. Ex.: 203.0.113.10/32"
  type        = string
}
