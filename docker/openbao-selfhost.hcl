ui = true
disable_mlock = true
plugin_directory = "/plugins"

listener "tcp" {
  address = "0.0.0.0:8200"
  cluster_address = "0.0.0.0:8201"
  tls_cert_file = "/bao/data/tls/server.pem"
  tls_key_file = "/bao/data/tls/server.pem"
  tls_min_version = "tls12"
}

storage "raft" {
  path = "/bao/data"
  node_id = "marty-selfhost-openbao"
}

api_addr = "https://openbao:8200"
cluster_addr = "https://openbao:8201"
