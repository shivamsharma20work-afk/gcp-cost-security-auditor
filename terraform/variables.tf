variable "project_id" {
  description = "Project that hosts the auditor (function, BigQuery, scheduler)"
  type        = string
}

variable "region" {
  type    = string
  default = "asia-south1"
}

variable "audit_projects" {
  description = "Projects to scan. Empty = scan only project_id."
  type        = list(string)
  default     = []
}

variable "schedule" {
  description = "Cron (Asia/Kolkata). Default: 9 AM every day."
  type        = string
  default     = "0 9 * * *"
}
