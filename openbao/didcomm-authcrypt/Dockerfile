# syntax=docker/dockerfile:1.7
FROM golang:1.26-alpine@sha256:c95332c2af86b6d89b91bd0500f4b9529ccbd090a0d1855c6d1ceaa142ae8615 AS build
WORKDIR /src/openbao/didcomm-authcrypt
COPY openbao/didcomm-authcrypt/go.mod openbao/didcomm-authcrypt/go.sum ./
RUN go mod download
COPY openbao/didcomm-authcrypt/ ./
RUN CGO_ENABLED=0 go test ./... && CGO_ENABLED=0 go vet ./...
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags='-s -w' -o /out/openbao-didcomm-authcrypt ./cmd/openbao-didcomm-authcrypt

FROM quay.io/openbao/openbao:2.5.5@sha256:6150c4a6b62067db6141c8da7a6a6b5763f4f47c315343d0c848b40fecdfd452
COPY --from=build --chmod=0555 /out/openbao-didcomm-authcrypt /plugins/openbao-didcomm-authcrypt
