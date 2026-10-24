
require "base64"
require "json"

payload = JSON.parse(Base64.decode64(ENV.fetch("CANVAS_LTI_SETUP_B64")))

if payload["public_host"]
  public_host = payload.fetch("public_host").to_s.strip
  updated_accounts = []
  if public_host.present?
    Account.all.find_each do |account|
      next unless account.respond_to?(:add_domain!)

      begin
        before_count = account.csp_domains.where(domain: public_host, workflow_state: "active").count if account.respond_to?(:csp_domains)
        account.add_domain!(public_host)
        after_count = account.csp_domains.where(domain: public_host, workflow_state: "active").count if account.respond_to?(:csp_domains)
        updated_accounts << account.id if before_count != after_count
      rescue ActiveRecord::RecordNotUnique
        # Idempotent when another seed pass already inserted the domain.
      end
    end
  end

  puts '__CANVAS_LTI_RESULT__' + JSON.generate({
    public_domain: {
      action: updated_accounts.empty? ? "unchanged" : "updated",
      host: public_host,
      default_host: HostUrl.default_host,
      accounts: Account.all.map { |account| { id: account.id, name: account.name, domain: account.domain } },
    },
  })
  exit
end

account = Account.find(payload.fetch("account_id"))
client_id = payload.fetch("client_id")

developer_key = DeveloperKey.find_or_initialize_by(name: client_id)
developer_key_action = developer_key.new_record? ? "created" : "updated"
developer_key.email = payload["admin_email"] if payload["admin_email"]
developer_key.scopes = payload.fetch("scopes", developer_key.scopes || [])
developer_key.redirect_uris = [payload.fetch("redirect_uri", developer_key.redirect_uris&.first)].compact
developer_key.notes = payload["notes"] if payload["notes"]
developer_key.is_lti_key = true if developer_key.respond_to?(:is_lti_key=)
if developer_key.respond_to?(:generate_rsa_keypair!) && developer_key.public_jwk.blank? && developer_key.public_jwk_url.blank?
  developer_key.generate_rsa_keypair!(overwrite: true)
end
developer_key.visible = true if developer_key.respond_to?(:visible=)
developer_key.require_scopes = true if developer_key.respond_to?(:require_scopes=)
developer_key.workflow_state = "active" if developer_key.respond_to?(:workflow_state=)
developer_key.save!

owner_binding = developer_key.owner_account.developer_key_account_bindings.where(developer_key: developer_key).first_or_initialize
owner_binding.workflow_state = "on" if owner_binding.respond_to?(:workflow_state=)
owner_binding.save! if owner_binding.new_record? || owner_binding.changed?

binding = developer_key.developer_key_account_bindings.where(account_id: account.id).first_or_initialize
binding.workflow_state = "on" if binding.respond_to?(:workflow_state=)
binding.save! if binding.new_record? || binding.changed?

result = {
  developer_key: {
    id: developer_key.id,
    action: developer_key_action,
        global_id: developer_key.global_id,
    name: developer_key.name,
    email: developer_key.email,
    redirect_uris: developer_key.redirect_uris,
    workflow_state: developer_key.workflow_state,
    visible: developer_key.visible,
    scopes: developer_key.scopes,
    notes: developer_key.notes,
        owner_binding_account_id: owner_binding.account_id,
        owner_binding_workflow_state: owner_binding.workflow_state,
        requested_binding_account_id: binding.account_id,
        requested_binding_workflow_state: binding.workflow_state,
  },
}

if payload["course_id"]
  course = Course.find(payload.fetch("course_id"))
  external_tool = ContextExternalTool.where(context: course).find_by(name: payload.fetch("display_name"))
  external_tool ||= ContextExternalTool.where(context: course).find_by(consumer_key: client_id)
  external_tool ||= ContextExternalTool.new(context: course, name: payload.fetch("display_name"))

  external_tool_action = external_tool.new_record? ? "created" : "updated"
  external_tool.name = payload.fetch("display_name")
  external_tool.url = payload.fetch("tool_url")
  external_tool.domain = payload.fetch("tool_domain")
  external_tool.consumer_key = client_id
  external_tool.shared_secret = "not-used-in-lti-1-3"
  external_tool.workflow_state = "public" if external_tool.respond_to?(:workflow_state=)
  external_tool.privacy_level = "public" if external_tool.respond_to?(:privacy_level=)
  external_tool.developer_key = developer_key if external_tool.respond_to?(:developer_key=)
  external_tool.lti_version = "1.3" if external_tool.respond_to?(:lti_version=)
  external_tool.settings = (external_tool.settings || {}).merge({
    "platform" => "canvas",
    "privacy_level" => "public",
    "icon_url" => nil,
    "text" => "ElevenID Credential Issuance",
  })
  external_tool.save!

  result[:external_tool] = {
    id: external_tool.id,
    action: external_tool_action,
    name: external_tool.name,
    url: external_tool.url,
    domain: external_tool.domain,
    consumer_key: external_tool.consumer_key,
        deployment_id: external_tool.respond_to?(:deployment_id) ? external_tool.deployment_id : nil,
    workflow_state: external_tool.workflow_state,
    developer_key_id: external_tool.developer_key_id,
    lti_version: external_tool.lti_version,
    settings: external_tool.settings,
  }
end

puts '__CANVAS_LTI_RESULT__' + JSON.generate(result)
