# frozen_string_literal: true

# Local override for Canvas production environment.
# Evaluated by production.rb via Dir glob: production-*.rb
#
# Enable Rails to serve static files (CSS, JS, images) from /usr/src/app/public
# when no Apache/nginx front-end is present inside the container.
Rails.application.configure do
  config.public_file_server.enabled = true

  # The readystack Canvas image can boot with a generated config/security.yml
  # that contains an encryption key but omits lti_iss. That breaks LTI 1.3
  # launches at runtime with `Validation failed: Iss can't be blank` when
  # Canvas builds the id_token for the tool launch.
  config.after_initialize do
    next unless defined?(Canvas::Security)

    env_lti_iss = ENV["CANVAS_REAL_LTI_ISS"].to_s.strip
    force_override = env_lti_iss.present?
    configured_lti_iss = force_override ? env_lti_iss : "http://localhost:8088"

    security_config = Canvas::Security.config
    security_config["lti_iss"] = configured_lti_iss if security_config["lti_iss"].blank? || force_override
  end
end
