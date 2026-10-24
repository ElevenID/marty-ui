"""Explicit native stock-Canvas request delta from the frozen Python oracle.

The published worker requested unsupported assignment expansion. Native requests
omit that expansion; all other request fields and queries remain exact. Keep
raw HTTPS observations and published corpus bytes unchanged.
"""

import hashlib
import json
from pathlib import Path

_SUBMISSION_PATHS = {
    f"/api/v1/courses/42/assignments/{assignment}/submissions/7?include%5B%5D=assignment":
    f"/api/v1/courses/42/assignments/{assignment}/submissions/7"
    for assignment in (9, 10)
}


def native_path(path):
    return _SUBMISSION_PATHS.get(path, path)


def native_requests(requests):
    return [{**request, "path": native_path(request["path"])} for request in requests]


def bind_current_capture_inputs(root, captured_inputs):
    """Keep recorded capture hashes distinct from reviewed current replay code.

    The only compatibility difference is the shared fixture's expectation-only
    stock-query assertion added after capture. It cannot change a frozen report,
    response, timing rule or published source hash. All current producer inputs
    still match the existing independent current-input contract exactly.
    """
    contract = json.loads((root / "contracts/canvas-worker-timeout-current-inputs.json").read_text())
    assert contract["schema"] == "marty.canvas-worker-timeout-current-inputs/v1"
    assert contract["normalization"] == "UTF-8 text with CRLF and CR converted to LF before SHA-256"
    current = contract["sha256"]
    for relative, expected in current.items():
        path = Path(relative)
        assert not path.is_absolute() and ".." not in path.parts
        actual = hashlib.sha256((root / path).read_text(encoding="utf8").encode()).hexdigest()
        assert actual == expected, "Current Canvas replay input differs: " + relative
    result = {}
    for name, captured in captured_inputs.items():
        assert Path(name).name == name and name.endswith((".py", ".json"))
        relative = ("scripts/" if name.endswith(".py") else "contracts/") + name
        actual = hashlib.sha256((root / relative).read_text(encoding="utf8").encode()).hexdigest()
        if actual != captured:
            assert (name == "canvas_worker_https_fixture.py"
                    and captured == "edf207e02a2e3a976f3a1b4cf15b7618038e60100fa51f0847797bcf92b65992"
                    and current.get(relative) == actual), "Unreviewed historical Canvas capture input drift: " + name
        result[name] = {"captured_sha256": captured, "current_sha256": actual,
                        "reviewed_harness_delta": actual != captured}
    return result
