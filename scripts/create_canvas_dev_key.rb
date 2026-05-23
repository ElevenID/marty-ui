# Create Canvas LTI developer key directly via Rails console
# Run with: docker exec -i marty-canvas-real bash -c "cd /usr/src/app && cat > /tmp/create_dev_key.rb && bin/rails runner /tmp/create_dev_key.rb -e production"

lti_base_url = ENV.fetch('CANVAS_LTI_EXPERIENCE_BASE_URL', 'https://beta.elevenidllc.com').sub(%r{/+$}, '')
platform_id = ENV.fetch('CANVAS_PLATFORM_ID', 'replace-with-canvas-platform-id')
redirect_uri = "#{lti_base_url}/v1/integrations/canvas/lti/platforms/#{platform_id}/experience"

# Create the developer key
key = DeveloperKey.create!(
  name: 'canvas-real-client-id',
  email: 'admin@example.com',
  developer_key_account_bindings_attributes: [
    { account_id: 1, workflow_state: 'on' }
  ],
  scopes: [
    'https://purl.imsglobal.org/spec/lti-ags/scope/lineitem',
    'https://purl.imsglobal.org/spec/lti-ags/scope/lineitem.readonly',
    'https://purl.imsglobal.org/spec/lti-ags/scope/result.readonly',
    'https://purl.imsglobal.org/spec/lti-nrps/scope/contextmembership.readonly',
  ],
  redirect_uris: redirect_uri,
  public_jwk_url: nil,
  is_lti_key: true,
  visible: true,
  workflow_state: 'active'
)

owner_binding = key.owner_account.developer_key_account_bindings.where(developer_key: key).first_or_initialize
owner_binding.workflow_state = 'on'
owner_binding.save! if owner_binding.new_record? || owner_binding.changed?

account_binding = Account.find(1).developer_key_account_bindings.where(developer_key: key).first_or_initialize
account_binding.workflow_state = 'on'
account_binding.save! if account_binding.new_record? || account_binding.changed?

puts "Developer key created: ID=#{key.id}, global_id=#{key.global_id}"
puts "Owner binding: account_id=#{owner_binding.account_id}, workflow_state=#{owner_binding.workflow_state}"
puts "Requested account binding: account_id=#{account_binding.account_id}, workflow_state=#{account_binding.workflow_state}"

# Generate Canvas signing keys
keys = Canvas::Oauth::KeyStorage.new_key
puts "Signing key generated: #{keys.inspect}"
puts "JWKS should now be populated."

# Verify
puts "Developer keys count: #{DeveloperKey.count}"
puts "JWKS endpoint keys: #{Canvas::Oauth::KeyStorage.public_keyset.as_json}"
