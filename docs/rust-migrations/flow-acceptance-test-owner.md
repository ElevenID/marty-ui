# Flow published-schema acceptance owner

The six outer Flow/admission cases and three nested public-startup cases moved
from `marty-canvas-acceptance` to the dedicated `marty-flow-acceptance` test
target without changing their names, fixtures, gate environment, or cleanup.
The Canvas runner compiles both targets in the same Bookworm phase, verifies
each artifact and exact Flow inventory, and runs them concurrently with the
worker and self-host targets. Failure in any owner fails the same protected
Canvas gate. The contracts lane excludes both acceptance packages.

On the Windows development host, the linked Canvas target lists 127 tests and
the linked Flow target lists exactly nine, with no overlapping names. The
protected Linux #1202 baseline listed 139 Canvas tests. Three unchanged
Canvas cases are platform-gated and absent from the Windows list:

- `canvas_mirror_worker_enabled_packaged_main_runs_and_shuts_down_cleanly`
  (`#[cfg(unix)]`)
- `runtime_failure_diagnostics::tests::linked_directory_marker_and_output_are_refused`
  (`#[cfg(unix)]`)
- `rendered_base_process::rendered_base_renewal_config_crosses_encryption_and_private_address_policy`
  (`#[cfg(target_os = "linux")]`)

Thus the expected protected Linux inventory is 130 Canvas + nine Flow =
the original 139 composition cases. The three Redis fixture unit tests and
two Gateway selection tests remain in Canvas-only wrappers around shared
implementations; the Flow target does not run duplicates or require a
special Cargo feature.

This split removes Canvas's direct `marty-flow` dev dependency, but a
`cargo tree -p marty-canvas-acceptance -i marty-flow` check still finds a
transitive path through `marty-gateway` and `marty-deployment-profile`.
Therefore no compile-surface or wall-time saving is claimed yet. The change
provides independent failure ownership and parallel execution; compare
protected Linux run timings before claiming a speed improvement.
