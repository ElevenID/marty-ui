# Local clock audit — 2026-09-07

The local Docker environment independently reproduced a wall-clock step large
enough to fail the Canvas deadline fixture's unchanged 0.5-second clock-agreement
guard. This limits **local timer qualification**, not implementation progress.
It does not establish a Rust behavior failure or identify which component
adjusted time. Hosted Linux verification remains the next qualification route.

## Observations

Read-only context: Docker Desktop, Linux kernel
`6.6.87.2-microsoft-standard-WSL2`, 24 CPUs, clocksource `tsc`; Windows 11 build
26200. The initial host CPU-load snapshot was 39%. No clocks, configuration,
runtime, fixture tolerances, frozen artifacts or deployments were changed.

One standard-library sampler ran in the exact existing immutable image:
`ghcr.io/elevenid/marty-credentials-issuance@sha256:9f15b64bc0ec7a693339cada3142b2952a575d2b50ee89230aabe078d0026176`.
It imported no application code and used no network, volumes or credentials.
Only relative elapsed times were emitted.

| Sample | Wall elapsed (s) | Monotonic elapsed (s) | Raw monotonic elapsed (s) | Wall minus monotonic (s) |
| --- | ---: | ---: | ---: | ---: |
| 0 | 0 | 0 | 0 | 0 |
| 2 | 2.000424 | 2.000422 | 1.941291 | 0.000002 |
| 3 | 2.056945 | 3.001870 | 2.913136 | -0.944925 |
| 30 | 29.072919 | 30.017844 | 29.030874 | -0.944925 |

Between samples 2 and 3, monotonic time advanced 1.001448 seconds but wall time
advanced only 0.056521 seconds: a relative step of approximately **-0.944927s**.
The offset then remained approximately -0.944925s for the rest of the sample.
The largest per-read monotonic bracket was 34.546 microseconds, far smaller than
the observed step. Boottime elapsed tracked monotonic elapsed.

Raw monotonic accumulated 29.030874s while monotonic accumulated 30.017844s.
That is a separate observed rate difference; this audit does not attribute a
mechanism or assume which clock is authoritative. In particular, it does not
claim a specific time-sync service, hypervisor action or host restart caused it.

A later, partially overlapping ten-second Windows UTC/Stopwatch sample showed
no comparable step: after its initial setup sample, wall-minus-Stopwatch offsets
stayed between 0.000087s and 0.000503s. That host sample began after the container's
early step, so it **does not prove the host clock was stable at that earlier
instant**. A separate daemon-versus-host query bracket placed the current wall
offset between -0.197s and -0.005s; it is not a simultaneous clock-history trace.

This independent observation is consistent with, but does not reconstruct, the
earlier worker failure: database elapsed 21.251852s was outside the expanded
monotonic bracket 21.5929737839906–22.594262666010763s. Both earlier successful
captures and failed later runs must remain in the evidence history.

## Exact primary sampling command

Run from PowerShell; the image was already present. No pull was performed.

```powershell
$canvasClockProbe = @'
import json, time
from pathlib import Path

def sample():
    before = time.monotonic_ns()
    wall = time.time_ns()
    raw = time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
    boot = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    after = time.monotonic_ns()
    return wall, (before + after) // 2, raw, boot, after - before

initial = sample()
observations = []
for index in range(31):
    current = initial if index == 0 else sample()
    wall, mono, raw, boot = [(current[i] - initial[i]) / 1e9 for i in range(4)]
    observations.append({'sample': index, 'wall_seconds': round(wall, 6), 'monotonic_seconds': round(mono, 6), 'raw_seconds': round(raw, 6), 'boottime_seconds': round(boot, 6), 'wall_minus_monotonic_seconds': round(wall - mono, 6), 'read_bracket_microseconds': round(current[4] / 1000, 3)})
    if index < 30:
        time.sleep(1)
source = Path('/sys/devices/system/clocksource/clocksource0/current_clocksource')
clocksource = source.read_text().strip() if source.exists() else 'unavailable'
assert all(c.isalnum() or c in '_-' for c in clocksource)
print(json.dumps({'clocksource': clocksource, 'observations': observations}, separators=(',', ':')))
'@
$canvasClockProbe | docker run --rm -i --network none --read-only --cap-drop ALL --security-opt no-new-privileges --entrypoint python ghcr.io/elevenid/marty-credentials-issuance@sha256:9f15b64bc0ec7a693339cada3142b2952a575d2b50ee89230aabe078d0026176 -
```

## Cleanup verification and limits

The primary sampler and host sampler both terminated successfully. The first
container used `--rm` but its generated identity was not recorded; bounded Docker
event queries did not yield a retained matching lifecycle record. Its exact
individual disappearance is therefore **not independently verified** by this
audit; successful `--rm` exit must not be presented as a recorded identity check.

A second, explicitly named five-second sample addressed that verification gap
without changing the primary evidence. Before launch, `docker container inspect
canvas-clock-audit-20260907-confirmation-v1` returned “No such container.” The
same immutable image and restrictions were used, adding
`--name canvas-clock-audit-20260907-confirmation-v1`. Its Python body was:

```python
import json,time
from pathlib import Path
initial=(time.time_ns(),time.monotonic_ns())
time.sleep(5)
current=(time.time_ns(),time.monotonic_ns())
print(json.dumps({'container_id_prefix':Path('/etc/hostname').read_text().strip(),'wall_seconds':(current[0]-initial[0])/1e9,'monotonic_seconds':(current[1]-initial[1])/1e9}))
```

It exited successfully, identified itself as `8f54c3397975`, and observed
5.000126320s wall versus 5.000126423s monotonic elapsed. Subsequent exact-name and
ID-prefix inspections both returned “No such container,” verifying removal of
that specific repeat container. The stable short repeat does not erase the
earlier step or qualify the longer deadline scenario.

No environment-repair patch, restart, clock adjustment, timer-bound relaxation,
runtime change, production action or beta deployment was performed.
