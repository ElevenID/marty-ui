"""Transport fixtures reach API assertions after a small wall-clock correction."""
import subprocess
import time

from tests.native_operator_https import https_json_server


def test_listener_clock_margin_preserves_time_and_ip_checks(tmp_path):
    before = time.time()
    with https_json_server(tmp_path, lambda *_: (200, {}), []) as server:
        command = ["openssl", "verify", "-CAfile", str(server.ca),
                   "-purpose", "sslserver", "-verify_ip", "127.0.0.1", "-attime"]
        for at, accepted in ((int(before - 30), True), (int(before - 120), False),
                             (int(before + 2 * 86400), False)):
            result = subprocess.run([*command, str(at), str(server.ca)],
                                    capture_output=True, check=False)
            assert (result.returncode == 0) is accepted
        wrong_ip = subprocess.run([
            "openssl", "verify", "-CAfile", str(server.ca), "-verify_ip", "127.0.0.2",
            str(server.ca),
        ], capture_output=True, check=False)
        assert wrong_ip.returncode != 0
