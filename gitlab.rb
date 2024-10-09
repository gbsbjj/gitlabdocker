# Configuração básica do GitLab

external_url 'https://gitlab.example.com'

# gitlab_rails['smtp_enable'] = true
# gitlab_rails['smtp_address'] = "smtp.example.com"
# gitlab_rails['smtp_port'] = 587
# gitlab_rails['smtp_user'] = "seu_email@example.com"
# gitlab_rails['smtp_password'] = "sua_senha"
# gitlab_rails['smtp_authentication'] = "login"
# gitlab_rails['smtp_enable_starttls_auto'] = true

# Monitoramento e Alertas
gitlab_rails['audit_events'] = %w(
  create_user update_user delete_user
  create_project update_project delete_project
  create_key update_key delete_key
  sign_in sign_out failed_sign_in
)

# gitlab_rails['gitlab_email_from'] = 'gitlab@example.com'
# gitlab_rails['db_password_file'] = '/etc/gitlab/encrypted_data_bags/db_password'

gitlab_rails['require_two_factor_authentication'] = true
gitlab_rails['password_expires_in'] = 90
gitlab_rails['password_length_minimum'] = 12
gitlab_rails['password_complexity'] = {
  'require_lower_case': true,
  'require_upper_case': true,
  'require_digit': true,
  'require_special': true
}
# gitlab_rails['omniauth']['providers']['google_oauth2'] = {
#   'label' => 'Google',
#   'client_id' => 'SEU_CLIENT_ID',
#   'client_secret' => 'SUA_CHAVE_SECRETA',
#   'scope' => 'email',
#   'redirect_uri' => 'http://seu-gitlab.example.com/users/auth/google_oauth2/callback'
# }

gitlab_rails['maximum_failed_logins'] = 3
gitlab_rails['lock_accounts_after_failed_attempts'] = true
# gitlab_rails['allowed_ip_ranges'] = ['192.168.0.0/24', '10.0.0.0/8']
# gitlab_rails['gitlab_shell_ssh_port'] = 2222

gitlab_rails['stuck_ci_jobs_worker_cron'] = "0 0 * * *"
gitlab_rails['expire_build_artifacts_worker_cron'] = "*/7 * * * *"
gitlab_rails['environments_auto_stop_cron_worker_cron'] = "24 * * * *"
gitlab_rails['pipeline_schedule_worker_cron'] = "19 * * * *"
gitlab_rails['ci_archive_traces_cron_worker_cron'] = "17 * * * *"
gitlab_rails['repository_check_worker_cron'] = "20 * * * *"
gitlab_rails['admin_email_worker_cron'] = "0 0 * * 0"
gitlab_rails['personal_access_tokens_expiring_worker_cron'] = "0 1 * * *"
gitlab_rails['personal_access_tokens_expired_notification_worker_cron'] = "0 2 * * *"
gitlab_rails['repository_archive_cache_worker_cron'] = "0 * * * *"
gitlab_rails['pages_domain_verification_cron_worker'] = "*/15 * * * *"
gitlab_rails['pages_domain_ssl_renewal_cron_worker'] = "*/10 * * * *"
gitlab_rails['pages_domain_removal_cron_worker'] = "47 0 * * *"
gitlab_rails['remove_unaccepted_member_invites_cron_worker'] = "10 15 * * *"
gitlab_rails['schedule_migrate_external_diffs_worker_cron'] = "15 * * * *"
gitlab_rails['ci_platform_metrics_update_cron_worker'] = '47 9 * * *'
gitlab_rails['analytics_usage_trends_count_job_trigger_worker_cron'] = "50 23 */1 * *"
gitlab_rails['member_invitation_reminder_emails_worker_cron'] = "0 0 * * *"
gitlab_rails['user_status_cleanup_batch_worker_cron'] = "* * * * *"
gitlab_rails['namespaces_in_product_marketing_emails_worker_cron'] = "0 9 * * *"
gitlab_rails['ssh_keys_expired_notification_worker_cron'] = "0 2 * * *"
gitlab_rails['ssh_keys_expiring_soon_notification_worker_cron'] = "0 1 * * *"
gitlab_rails['loose_foreign_keys_cleanup_worker_cron'] = "*/5 * * * *"
gitlab_rails['ci_runner_versions_reconciliation_worker_cron'] = "@daily"
gitlab_rails['ci_runners_stale_machines_cleanup_worker_cron'] = "36 * * * *"
gitlab_rails['ci_catalog_resources_process_sync_events_worker_cron'] = "*/1 * * * *"
gitlab_rails['ci_click_house_finished_pipelines_sync_worker_cron'] = "*/4 * * * *"
gitlab_rails['ci_click_house_finished_pipelines_sync_worker_args'] = [1]

gitlab_rails['content_security_policy'] = {
 'enabled' => false,
 'report_only' => false,
 'directives' => {
   'base_uri' => nil,
   'child_src' => nil,
   'connect_src' => nil,
   'default_src' => nil,
   'font_src' => nil,
   'form_action' => nil,
   'frame_ancestors' => nil,
   'frame_src' => nil,
   'img_src' => nil,
   'manifest_src' => nil,
   'media_src' => nil,
   'object_src' => nil,
   'script_src' => nil,
   'style_src' => nil,
   'worker_src' => nil,
   'report_uri' => nil,
 }
}

gitlab_rails['allowed_hosts'] = ['gitlab.example.com', 'www.gitlab.example.com']

gitlab_rails['monitoring_whitelist'] = ['127.0.0.0/8', '::1/128']

### CI Secure Files
# gitlab_rails['ci_secure_files_enabled'] = true
# gitlab_rails['ci_secure_files_storage_path'] = "/var/opt/gitlab/gitlab-rails/shared/ci_secure_files"
# gitlab_rails['ci_secure_files_object_store_enabled'] = false
# gitlab_rails['ci_secure_files_object_store_remote_directory'] = "ci-secure-files"
# gitlab_rails['ci_secure_files_object_store_connection'] = {
#   'provider' => 'AWS',
#   'region' => 'eu-west-1',
#   'aws_access_key_id' => 'AWS_ACCESS_KEY_ID',
#   'aws_secret_access_key' => 'AWS_SECRET_ACCESS_KEY',
#   # # The below options configure an S3 compatible host instead of AWS
#   # 'host' => 's3.amazonaws.com',
#   # 'aws_signature_version' => 4, # For creation of signed URLs. Set to 2 if provider does not support v4.
#   # 'endpoint' => 'https://s3.amazonaws.com', # default: nil - Useful for S3 compliant services such as DigitalOcean Spaces
#   # 'path_style' => false # Use 'host/bucket_name/object' instead of 'bucket_name.host/object'
# }

### GitLab Pages
# gitlab_rails['pages_object_store_enabled'] = false
# gitlab_rails['pages_object_store_remote_directory'] = "pages"
# gitlab_rails['pages_object_store_connection'] = {
#   'provider' => 'AWS',
#   'region' => 'eu-west-1',
#   'aws_access_key_id' => 'AWS_ACCESS_KEY_ID',
#   'aws_secret_access_key' => 'AWS_SECRET_ACCESS_KEY',
#   # # The below options configure an S3 compatible host instead of AWS
#   # 'host' => 's3.amazonaws.com',
#   # 'aws_signature_version' => 4, # For creation of signed URLs. Set to 2 if provider does not support v4.
#   # 'endpoint' => 'https://s3.amazonaws.com', # default: nil - Useful for S3 compliant services such as DigitalOcean Spaces
#   # 'path_style' => false # Use 'host/bucket_name/object' instead of 'bucket_name.host/object'
# }
# gitlab_rails['pages_local_store_enabled'] = true
# gitlab_rails['pages_local_store_path'] = "/var/opt/gitlab/gitlab-rails/shared/pages"

### OmniAuth Settings
###! Docs: https://docs.gitlab.com/ee/integration/omniauth.html
# gitlab_rails['omniauth_enabled'] = nil
# gitlab_rails['omniauth_allow_single_sign_on'] = ['saml']
# gitlab_rails['omniauth_sync_email_from_provider'] = 'saml'
# gitlab_rails['omniauth_sync_profile_from_provider'] = ['saml']
# gitlab_rails['omniauth_sync_profile_attributes'] = ['email']
# gitlab_rails['omniauth_auto_sign_in_with_provider'] = 'saml'
# gitlab_rails['omniauth_block_auto_created_users'] = true
# gitlab_rails['omniauth_auto_link_ldap_user'] = false
# gitlab_rails['omniauth_auto_link_saml_user'] = false
# gitlab_rails['omniauth_auto_link_user'] = ['twitter']
# gitlab_rails['omniauth_external_providers'] = ['twitter', 'google_oauth2']
# gitlab_rails['omniauth_allow_bypass_two_factor'] = ['google_oauth2']
# gitlab_rails['omniauth_providers'] = [
#   {
#     "name" => "google_oauth2",
#     "app_id" => "YOUR APP ID",
#     "app_secret" => "YOUR APP SECRET",
#     "args" => { "access_type" => "offline", "approval_prompt" => "" }
#   }
# ]
# gitlab_rails['omniauth_cas3_session_duration'] = 28800
# gitlab_rails['omniauth_saml_message_max_byte_size'] = 250000

nginx['redirect_http_to_https'] = false
#nginx['custom_nginx_config'] = "include /etc/gitlab/nginx/sites-enabled/*.conf;"
nginx['cache_max_size'] = "10g"
nginx['cache_use_temp_path'] = true
#nginx['gzip'] = 'on'
#nginx['gzip_comp_level'] = '6'
#nginx['gzip_types'] = 'text/plain text/css text/javascript application/x-javascript application/xml application/atom+xml';
# nginx['ssl_certificate'] = '/etc/gitlab/ssl/certs/gitlab.crt'
# nginx['ssl_certificate_key'] = '/etc/gitlab/ssl/private/gitlab.key'
# nginx['proxy_set_headers'] = {
#   'Host' => '$host',
#   'X-Real-IP' => '$remote_addr',
#   'X-Forwarded-For' => '$proxy_add_x_forwarded_for'
# }
nginx['custom_nginx_config'] = <<~EOS
  add_header X-Frame-Options "DENY";
  add_header Referrer-Policy "strict-origin-when-cross-origin";
EOS
nginx['keepalive_timeout'] = 65
nginx['ssl_protocols'] = 'TLSv1 TLSv1.1 TLSv1.2'
