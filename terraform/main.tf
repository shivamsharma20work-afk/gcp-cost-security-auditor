terraform {
  required_version = ">= 1.9"
  required_providers {
    google  = { source = "hashicorp/google", version = "~> 6.0" }
    archive = { source = "hashicorp/archive", version = "~> 2.6" }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

locals {
  name           = "cost-security-auditor"
  audit_projects = length(var.audit_projects) > 0 ? var.audit_projects : [var.project_id]
}

resource "google_project_service" "apis" {
  for_each = toset([
    "cloudfunctions.googleapis.com",
    "run.googleapis.com",
    "cloudbuild.googleapis.com",
    "artifactregistry.googleapis.com",
    "cloudscheduler.googleapis.com",
    "compute.googleapis.com",
    "monitoring.googleapis.com",
    "bigquery.googleapis.com",
    "secretmanager.googleapis.com",
  ])
  service            = each.value
  disable_on_destroy = false
}

# --- Identity: read-only scanner ----------------------------------------------

resource "google_service_account" "auditor" {
  account_id   = "auditor-fn"
  display_name = "Cost & security auditor (read-only)"
}

# Viewer roles on every audited project. The auditor can see, never change.
resource "google_project_iam_member" "auditor_read" {
  for_each = {
    for pair in setproduct(local.audit_projects, ["roles/compute.viewer", "roles/monitoring.viewer"]) :
    "${pair[0]}/${pair[1]}" => { project = pair[0], role = pair[1] }
  }
  project = each.value.project
  role    = each.value.role
  member  = "serviceAccount:${google_service_account.auditor.email}"
}

# --- BigQuery: findings history -----------------------------------------------

resource "google_bigquery_dataset" "audit" {
  dataset_id                 = "audit"
  location                   = var.region
  delete_contents_on_destroy = true
  depends_on                 = [google_project_service.apis]
}

resource "google_bigquery_table" "findings" {
  dataset_id          = google_bigquery_dataset.audit.dataset_id
  table_id            = "findings"
  deletion_protection = false

  time_partitioning {
    type          = "DAY"
    field         = "scanned_at"
    expiration_ms = 180 * 24 * 3600 * 1000 # keep 6 months
  }
  clustering = ["project", "check", "severity"]

  schema = jsonencode([
    { name = "project", type = "STRING", mode = "REQUIRED" },
    { name = "category", type = "STRING", mode = "REQUIRED" },
    { name = "check", type = "STRING", mode = "REQUIRED" },
    { name = "severity", type = "STRING", mode = "REQUIRED" },
    { name = "resource", type = "STRING", mode = "REQUIRED" },
    { name = "location", type = "STRING" },
    { name = "detail", type = "STRING" },
    { name = "est_monthly_cost_usd", type = "FLOAT" },
    { name = "scanned_at", type = "TIMESTAMP", mode = "REQUIRED" },
  ])
}

# Write access to this one dataset only
resource "google_bigquery_dataset_iam_member" "auditor_write" {
  dataset_id = google_bigquery_dataset.audit.dataset_id
  role       = "roles/bigquery.dataEditor"
  member     = "serviceAccount:${google_service_account.auditor.email}"
}

# --- Secret: Slack webhook (value added out-of-band, never in Terraform state) -

resource "google_secret_manager_secret" "slack" {
  secret_id = "auditor-slack-webhook"
  replication {
    auto {}
  }
  depends_on = [google_project_service.apis]
}

resource "google_secret_manager_secret_iam_member" "auditor_slack" {
  secret_id = google_secret_manager_secret.slack.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.auditor.email}"
}

# --- Cloud Function (gen2) ----------------------------------------------------

resource "google_storage_bucket" "source" {
  name                        = "${var.project_id}-auditor-src"
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = true
}

data "archive_file" "fn" {
  type        = "zip"
  source_dir  = "${path.module}/../build/function"
  output_path = "${path.module}/../build/function.zip"
}

resource "google_storage_bucket_object" "fn" {
  # Hash in the name -> a code change uploads a new object and redeploys the function
  name   = "function-${data.archive_file.fn.output_md5}.zip"
  bucket = google_storage_bucket.source.name
  source = data.archive_file.fn.output_path
}

resource "google_cloudfunctions2_function" "auditor" {
  name     = local.name
  location = var.region

  build_config {
    runtime     = "python312"
    entry_point = "run_audit"
    source {
      storage_source {
        bucket = google_storage_bucket.source.name
        object = google_storage_bucket_object.fn.name
      }
    }
  }

  service_config {
    service_account_email = google_service_account.auditor.email
    available_memory      = "512M"
    timeout_seconds       = 540
    max_instance_count    = 1
    ingress_settings      = "ALLOW_INTERNAL_ONLY"

    environment_variables = {
      AUDIT_PROJECTS = join(",", local.audit_projects)
      BQ_TABLE       = "${var.project_id}.${google_bigquery_dataset.audit.dataset_id}.${google_bigquery_table.findings.table_id}"
    }

    secret_environment_variables {
      key        = "SLACK_WEBHOOK_URL"
      project_id = var.project_id
      secret     = google_secret_manager_secret.slack.secret_id
      version    = "latest"
    }
  }

  depends_on = [
    google_project_service.apis,
    google_secret_manager_secret_iam_member.auditor_slack,
  ]
}

# --- Scheduler: run daily, authenticated with OIDC ---------------------------

resource "google_service_account" "scheduler" {
  account_id   = "auditor-scheduler"
  display_name = "Invokes the auditor function"
}

resource "google_cloud_run_service_iam_member" "scheduler_invoke" {
  location = var.region
  service  = google_cloudfunctions2_function.auditor.name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.scheduler.email}"
}

resource "google_cloud_scheduler_job" "daily" {
  name             = "${local.name}-daily"
  schedule         = var.schedule
  time_zone        = "Asia/Kolkata"
  attempt_deadline = "600s"

  retry_config { retry_count = 1 }

  http_target {
    http_method = "POST"
    uri         = google_cloudfunctions2_function.auditor.service_config[0].uri
    oidc_token {
      service_account_email = google_service_account.scheduler.email
      audience              = google_cloudfunctions2_function.auditor.service_config[0].uri
    }
  }

  depends_on = [google_project_service.apis]
}
