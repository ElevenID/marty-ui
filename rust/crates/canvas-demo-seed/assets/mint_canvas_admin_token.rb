
require "base64"
require "json"

payload = JSON.parse(Base64.decode64(ENV.fetch("CANVAS_ADMIN_TOKEN_SETUP_B64")))
pseudonym = Pseudonym.find_by!(unique_id: payload.fetch("admin_email"))
token = pseudonym.user.access_tokens.create!(purpose: "ElevenID Canvas demo seed")
token.workflow_state = "active" if token.respond_to?(:workflow_state=)
token.save! if token.changed?
puts '__CANVAS_ADMIN_TOKEN__' + token.full_token
