from scripts.run_canvas_oss_lifecycle import unexpected_running_services


def test_lifecycle_allows_only_the_compose_continuity_monitor() -> None:
    assert unexpected_running_services(["canvas-continuity-monitor"]) == []


def test_lifecycle_rejects_preexisting_canvas_data_plane_services() -> None:
    assert unexpected_running_services(
        ["canvas-continuity-monitor", "canvas-postgres", "canvas-web"]
    ) == ["canvas-postgres", "canvas-web"]
