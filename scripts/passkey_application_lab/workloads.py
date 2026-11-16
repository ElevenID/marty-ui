"""Keyless workload TLS for the owned real-service Badge fixture."""

import pathlib
import urllib.parse

from cryptography import x509
from cryptography.hazmat.primitives import serialization


class WorkloadMixin:
    SERVER_ROLES = {
        "event-stream",
        "organization",
        "credential-template",
        "revocation-profile",
        "auth",
        "flow",
        "presentation-policy",
        "issuance-native",
    }
    CLIENT_PREFIX = {
        "auth": "GRPC_WORKLOAD_TLS_CLIENT",
        "flow": "GRPC_WORKLOAD_TLS_CLIENT",
        "gateway": "GRPC_WORKLOAD_TLS_CLIENT",
        "verification": "GRPC_WORKLOAD_TLS",
        "compliance-profile": "GRPC_WORKLOAD_TLS",
        "deployment-profile": "GRPC_WORKLOAD_TLS",
    }
    CA_FIELDS = {
        "organization": ["ES_GRPC_CA_CERT"],
        "credential-template": ["ORG_GRPC_CA_CERT", "RP_GRPC_CA_CERT"],
        "presentation-policy": ["ORG_GRPC_CA_CERT"],
        "issuance-native": ["GRPC_TLS_CA_CERT"],
        "trust-profile": ["ORG_GRPC_CA_CERT"],
        "revocation-profile": ["ORG_GRPC_CA_CERT"],
        "device-registration": ["ORG_GRPC_CA_CERT"],
        "gateway": ["ORG_GRPC_CA_CERT", "ES_GRPC_CA_CERT", "GRPC_TLS_CA_CERT"],
        "applicant": ["ES_GRPC_CA_CERT"],
    }

    def make_workloads(self):
        folder = pathlib.Path(self.scratch.name)
        mount = "passkey-workload-pki-" + self.suffix
        self.bao("write", "-format=json", "sys/mounts/" + mount, "type=pki")
        root = self.bao(
            "write",
            "-format=json",
            mount + "/root/generate/internal",
            "common_name=Disposable Marty Workload CA",
            "ttl=1h",
            "key_type=ec",
            "key_bits=256",
        )["data"]["certificate"]
        ca = folder / "workload-ca.crt"
        ca.write_text(root, encoding="ascii")
        records = {}
        for kind, roles in [
            ("server", sorted(self.SERVER_ROLES)),
            ("client", sorted(self.CLIENT_PREFIX)),
        ]:
            for role in roles:
                label = role + "-" + kind
                key = "passkey-workload-" + self.suffix + "-" + label
                uri = "spiffe://marty.internal/service/" + role
                self.bao(
                    "write",
                    "-format=json",
                    mount + "/roles/" + label,
                    "allowed_domains=" + role,
                    "allow_bare_domains=true",
                    "allow_subdomains=false",
                    "allowed_uri_sans=" + uri,
                    "max_ttl=30m",
                    "key_type=ec",
                    "key_bits=256",
                    "use_csr_common_name=false",
                    "use_csr_sans=false",
                    "server_flag=" + str(kind == "server").lower(),
                    "client_flag=" + str(kind == "client").lower(),
                )
                self.bao(
                    "write",
                    "-format=json",
                    "transit/keys/" + key,
                    "type=ecdsa-p256",
                    "exportable=false",
                    "allow_plaintext_backup=false",
                )
                metadata = self.bao("read", "-format=json", "transit/keys/" + key)[
                    "data"
                ]
                assert (
                    metadata["exportable"] is False
                    and metadata["allow_plaintext_backup"] is False
                )
                csr = self.bao(
                    "write", "-format=json", "transit/keys/" + key + "/csr", "version=1"
                )["data"]["csr"]
                request = x509.load_pem_x509_csr(csr.encode())
                assert request.is_signature_valid
                leaf = self.bao(
                    "write",
                    "-format=json",
                    mount + "/sign/" + label,
                    "csr=" + csr,
                    "common_name=" + role,
                    "alt_names=" + role,
                    "uri_sans=" + uri,
                    "ttl=25m",
                )["data"]["certificate"]
                certificate = x509.load_pem_x509_certificate(leaf.encode())
                certificate.verify_directly_issued_by(
                    x509.load_pem_x509_certificate(root.encode())
                )
                assert certificate.public_key().public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                ) == request.public_key().public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                assert certificate.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName
                ).value.get_values_for_type(x509.UniformResourceIdentifier) == [uri]
                assert "PRIVATE KEY" not in csr + leaf + root
                chain = folder / (label + ".crt")
                chain.write_text(leaf + "\n" + root, encoding="ascii")
                policy = f'path "transit/keys/{key}" {{ capabilities=["read"] }}\npath "transit/sign/{key}" {{ capabilities=["update"] }}\npath "transit/sign/{key}/*" {{ capabilities=["update"] }}\n'
                token = self.child_token(
                    "passkey-workload-" + self.suffix + "-" + label, policy
                )
                token_file = folder / (label + ".token")
                token_file.write_text(token, encoding="ascii")
                records[(role, kind)] = {
                    "key": key,
                    "chain": chain,
                    "token": token_file,
                }
        self.note(
            "Verified14 independent non-exportable workload keys, signed CSRs and exact SPIFFE role certificates"
        )
        return ca, records

    def start(self, name, image, env=None, mounts=(), **kwargs):
        if name == "front":
            self.workload_ca, self.workloads = self.make_workloads()
        env = dict(env or {})
        mounts = list(mounts)
        if (
            name in self.SERVER_ROLES
            or name in self.CLIENT_PREFIX
            or name in self.CA_FIELDS
        ):
            mounts.append((self.workload_ca, "/run/lab/workload-ca.crt"))
        if (name in self.SERVER_ROLES or name in self.CLIENT_PREFIX) and not any(
            str(target) == "/run/lab/ca.crt" for source, target in mounts
        ):
            mounts.append(
                (pathlib.Path(self.scratch.name) / "ca.crt", "/run/lab/ca.crt")
            )
        for kind, prefix in [
            ("server", "GRPC_WORKLOAD_TLS_SERVER"),
            ("client", self.CLIENT_PREFIX.get(name)),
        ]:
            if prefix is None or (name, kind) not in getattr(self, "workloads", {}):
                continue
            record = self.workloads[(name, kind)]
            chain = "/run/lab/workload-" + kind + ".crt"
            token = "/run/lab/workload-" + kind + ".token"
            mounts.extend([(record["chain"], chain), (record["token"], token)])
            certificate_field = (
                "GRPC_WORKLOAD_TLS_CLIENT_CERT"
                if prefix == "GRPC_WORKLOAD_TLS"
                else prefix + "_CERT"
            )
            env.update(
                {
                    certificate_field: chain,
                    prefix + "_KMS_ADDR": "https://openbao:8200",
                    prefix + "_KMS_CA_CERT": "/run/lab/ca.crt",
                    prefix + "_KMS_TOKEN_FILE": token,
                    prefix + "_KMS_KEY_NAME": record["key"],
                    prefix + "_KMS_KEY_VERSION": "1",
                }
            )
            if name in self.CLIENT_PREFIX or name in {
                "auth",
                "flow",
                "presentation-policy",
                "issuance-native",
            }:
                env["GRPC_WORKLOAD_TLS_CA_CERT"] = "/run/lab/workload-ca.crt"
        for key in self.CA_FIELDS.get(name, []):
            env[key] = "/run/lab/workload-ca.crt"
        for key, value in tuple(env.items()):
            if key.endswith("_GRPC_TARGET"):
                parsed = urllib.parse.urlparse(
                    value if "://" in value else "http://" + value
                )
                if parsed.hostname in self.SERVER_ROLES:
                    env[key] = "https://" + parsed.netloc
        return super().start(name, image, env=env, mounts=mounts, **kwargs)
