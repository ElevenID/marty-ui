ui = true
disable_mlock = true

listener "tcp" {
  address = "0.0.0.0:8200"
  tls_disable = 1
}

storage "file" {
  path = "/bao/data/storage"
}

api_addr = "http://openbao:8200"
cluster_addr = "http://openbao:8201"