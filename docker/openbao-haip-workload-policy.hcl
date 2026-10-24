# Signing-keys alone uses this token after authorizing the internal caller.
# Provision it without the default policy; do not grant Transit, DIDComm pack,
# generic secret reads, or plugin administration to this workload token.
path "didcomm/haip/keys/*" {
  capabilities = ["create", "update", "read"]
}

path "didcomm/haip/decrypt/*" {
  capabilities = ["update"]
}
