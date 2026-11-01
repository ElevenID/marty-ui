# Installer-only local control channel. /bao/control is a private socket child
# of the operator-owned installation mount, owned 0700 by the OpenBao image UID.
# All three Unix permission settings are required by OpenBao 2.5.5's factory.
ui = true
disable_mlock = true
plugin_directory = "/plugins"

# Fresh installer deployments use their own customer-protected static key.
# This projection is mounted read-only into OpenBao alone, outside Raft data.
seal "static" {
  current_key_id = "marty-selfhost-static-v1"
  current_key = "file:///bao/seal/static.key"
}

listener "tcp" {
  address = "0.0.0.0:8200"
  cluster_address = "0.0.0.0:8201"
  tls_cert_file = "/bao/data/tls/server.pem"
  tls_key_file = "/bao/data/tls/server.pem"
  tls_min_version = "tls12"
}

listener "unix" {
  address = "/bao/control/api.sock"
  socket_mode = "0600"
  socket_user = "openbao"
  socket_group = "openbao"
}

storage "raft" {
  path = "/bao/data"
  node_id = "marty-selfhost-openbao"
}

api_addr = "https://openbao:8200"
cluster_addr = "https://openbao:8201"
