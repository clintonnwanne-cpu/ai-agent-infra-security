variable "aws_region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "us-east-2"
}

variable "operator_public_access_cidrs" {
  description = "Explicitly approved operator IPv4 CIDRs for the public EKS API. Required; no open-access fallback. Approval and address ownership must be reviewed separately."
  type        = list(string)
  nullable    = false

  validation {
    condition = try(length(var.operator_public_access_cidrs) > 0 && alltrue([
      for cidr in var.operator_public_access_cidrs : can(cidrnetmask(cidr)) && try(tonumber(split("/", cidr)[1]) > 0, false)
    ]), false)
    error_message = "Supply a nonempty list of approved IPv4 CIDRs with prefixes 1 through 32; null, malformed, IPv6 and /0 values are forbidden."
  }
}

variable "cluster_name" {
  description = "Name prefix for all resources"
  type        = string
  default     = "ai-agent-security-lab"
}

variable "kubernetes_version" {
  description = "EKS Kubernetes version"
  type        = string
  default     = "1.31"
}

variable "environment" {
  description = "Environment tag"
  type        = string
  default     = "demo"
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "availability_zones" {
  description = "AZs to deploy subnets into"
  type        = list(string)
  default     = ["us-east-2a", "us-east-2b"]
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for private subnets"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24"]
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for public subnets"
  type        = list(string)
  default     = ["10.0.101.0/24", "10.0.102.0/24"]
}

variable "agent_namespace" {
  description = "Kubernetes namespace where the AI agent runs"
  type        = string
  default     = "ai-agent"
}

variable "agent_service_account" {
  description = "Kubernetes ServiceAccount name for the AI agent"
  type        = string
  default     = "ai-agent-sa"
}
