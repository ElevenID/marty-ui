# Emit only allowlisted numeric counters from the public-image compiler cache.
# No cache coordinates, paths, source text, credentials, or raw backend output.
BEGIN {
    if (phase != "release_binaries" && phase != "dependency_cook") {
        exit 2
    }
    labels["Compile requests"] = "compile_requests"
    labels["Compile requests executed"] = "compile_requests_executed"
    labels["Cache hits"] = "cache_hits"
    labels["Cache hits (Rust)"] = "cache_hits_rust"
    labels["Cache misses"] = "cache_misses"
    labels["Cache misses (Rust)"] = "cache_misses_rust"
    labels["Cache timeouts"] = "cache_timeouts"
    labels["Cache read errors"] = "cache_read_errors"
    labels["Cache write errors"] = "cache_write_errors"
    labels["Non-cacheable compilations"] = "non_cacheable_compilations"
    labels["Non-cacheable calls"] = "non_cacheable_calls"
    labels["Unsupported compiler calls"] = "unsupported_compiler_calls"
    order = "compile_requests compile_requests_executed cache_hits cache_hits_rust cache_misses cache_misses_rust cache_timeouts cache_read_errors cache_write_errors non_cacheable_compilations non_cacheable_calls unsupported_compiler_calls"
    count = split(order, ordered, " ")
}
{
    line = $0
    sub(/^[[:space:]]+/, "", line)
    sub(/[[:space:]]+$/, "", line)
    fields = split(line, parts, /[[:space:]][[:space:]]+/)
    if (fields == 2 && parts[1] in labels && parts[2] ~ /^[0-9]+$/) {
        counters[labels[parts[1]]] = parts[2]
    }
}
END {
    first = 1
    for (counter_idx = 1; counter_idx <= count; counter_idx++) {
        key = ordered[counter_idx]
        if (key in counters) {
            if (first) {
                printf "MARTY_PUBLIC_SCCACHE_V1 {\"phase\":\"%s\",\"counters\":{", phase
                first = 0
            } else {
                printf ","
            }
            printf "\"%s\":%s", key, counters[key]
        }
    }
    if (!first) {
        print "}}"
    }
}
