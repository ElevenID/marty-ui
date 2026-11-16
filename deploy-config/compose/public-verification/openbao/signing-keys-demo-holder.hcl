# Attach only to the Signing Keys custody workload, never to Flow's MAC minter.
# Wildcards also match subpaths: the closed parameter set blocks import/config.
path "transit/keys/demo-holder-*" {
  capabilities = ["create", "update", "read"]
  allowed_parameters = { "type" = ["ecdsa-p256"] }
}
path "transit/sign/demo-holder-*" {
  capabilities = ["update"]
  required_parameters = ["input", "prehashed", "hash_algorithm"]
  allowed_parameters = { "input" = [], "prehashed" = [true, "true"], "hash_algorithm" = ["sha2-256"], "key_version" = [] }
}
