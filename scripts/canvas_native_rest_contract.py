"""Explicit native stock-Canvas request delta from the frozen Python oracle.

The published worker requested unsupported assignment expansion. Native requests
omit that expansion; all other request fields and queries remain exact. Keep
raw HTTPS observations and published corpus bytes unchanged.
"""

_SUBMISSION_PATHS = {
    f"/api/v1/courses/42/assignments/{assignment}/submissions/7?include%5B%5D=assignment":
    f"/api/v1/courses/42/assignments/{assignment}/submissions/7"
    for assignment in (9, 10)
}


def native_path(path):
    return _SUBMISSION_PATHS.get(path, path)


def native_requests(requests):
    return [{**request, "path": native_path(request["path"])} for request in requests]
