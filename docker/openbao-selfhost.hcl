ui = true
disable_mlock = true
plugin_directory = "/plugins"

listener "tcp" {
  address = "0.0.0.0:8200"
  cluster_address = "0.0.0.0:8201"
  tls_disable = 1
}

storage "raft" {
  path = "/bao/data"
  node_id = "marty-selfhost-openbao"
}

api_addr = "http://openbao:8200"
cluster_addr = "https://openbao:8201"
