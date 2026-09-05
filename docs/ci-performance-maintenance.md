# Maintaining fast CI without reducing coverage

## Adopt refreshed UI timings through review

The background refresh uploads data; it does not change the checked-in shard
weights. To complete the feedback loop, select a successful `Refresh UI Test
Timings` run associated with successful CI for a reviewed, merged revision:

```sh
gh run list --repo ElevenID/marty-ui --workflow refresh-ui-test-timings.yml
gh run view RUN_ID --repo ElevenID/marty-ui
gh run download RUN_ID --repo ElevenID/marty-ui --name ui-vitest-timings-refreshed --dir /path/to/new/temporary/directory
node ui/scripts/adopt-vitest-timings.mjs /path/to/new/temporary/directory/ui-vitest.json
node ui/scripts/run-vitest-shard.mjs --plan 4
git diff -- .github/test-timings/ui-vitest.json
```

Commit the timing-file diff on a branch and submit a normal PR. Do not bypass
checks or auto-merge observations from unreviewed source revisions. The adoption
script rejects malformed data, oversized files, invalid paths and unbounded
durations; removed test paths are discarded and new tests retain fallback weights.
The shard planner always discovers the current tests independently of timings.

## Compiler caches

PR and merge-queue jobs only read compiler and image caches. The main-branch
warmer publishes both debug/test and release compiler outputs. Docker receives
short-lived cache credentials through BuildKit secrets, never build arguments
or image environment variables. Layer-cache misses can reuse release compiler
outputs without changing production optimization or smoke-test coverage.

Compare cold and warm runs separately. sccache hit rates exclude non-cacheable
calls, so also inspect test executable compilation/linking and wall-clock time.
Six independent in-memory issuance test modules now share `issuance-behavior`;
their assertions and fixtures are unchanged. Filter by module to run one group:

```sh
cargo test --manifest-path rust/Cargo.toml -p marty-issuance-service --test issuance-behavior canvas_worker_result_oracle
```

## Renewal contracts

The frozen renewal outcome matrix still exercises all 60 combinations with the
real worker, PostgreSQL clock, 20-second renewals and 30-second deadlines. Its three
write-failure groups run concurrently in uniquely named disposable databases.
The configured contract database must remain a dedicated `*_test` database and
its PostgreSQL role must have `CREATEDB`. Each group closes connections and drops
only the database it created, including when an assertion fails. Other database
and process-signal contracts remain serialized and unchanged.
