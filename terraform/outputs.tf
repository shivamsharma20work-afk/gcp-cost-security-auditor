output "function_uri" {
  value = google_cloudfunctions2_function.auditor.service_config[0].uri
}

output "findings_table" {
  value = "${var.project_id}.${google_bigquery_dataset.audit.dataset_id}.${google_bigquery_table.findings.table_id}"
}

output "slack_secret" {
  description = "Add the webhook: echo -n URL | gcloud secrets versions add <this> --data-file=-"
  value       = google_secret_manager_secret.slack.secret_id
}
