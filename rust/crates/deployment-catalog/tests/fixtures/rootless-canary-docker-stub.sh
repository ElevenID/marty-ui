#!/bin/sh
# Test-only Docker responses; each runner owns a separate private working dir.
set -eu
case "${PWD##*/}" in
    .installer-command-*) ;;
    *) exit 73 ;;
esac
base=$(dirname "$PWD")
case "$1" in
info)
printf '%s\n' '{"id":"development-mock-engine","os":"linux","architecture":"x86_64","server_version":"29.9.2","security_options":["name=seccomp,profile=builtin"]}'
;;
compose)
if [ "$#" != 3 ] || [ "$2" != version ] || [ "$3" != --short ]; then
    printf 'UNEXPECTED:compose\n' >> "$base/trace"
    exit 72
fi
printf '2.40.3\n'
;;
ps) printf 'ps\n' >> "$base/trace" ;;
create)
printf 'create\n' >> "$base/trace"
receipt=$(cat "$base/receipt-name")
if [ -e "$base/installation/evidence/$receipt" ]; then
    printf 'receipt-present-before-create\n' >> "$base/trace"
else
    printf 'receipt-absent-before-create\n' >> "$base/trace"
fi
if [ "$(cat "$base/create-mode")" = drift-journal ]; then
    cat "$base/changed-journal.json" > "$base/installation/installation.json"
    printf 'journal-drift\n' >> "$base/trace"
fi
cat "$base/container-id"
;;
inspect)
printf 'inspect\n' >> "$base/trace"
receipt=$(cat "$base/receipt-name")
cmp -s "$base/installation/evidence/$receipt" "$base/expected-provisional.json"
[ "$(stat -c %a "$base/installation/evidence/$receipt")" = 600 ]
printf 'provisional-readback-before-inspect\n' >> "$base/trace"
[ "$(cat "$base/inspect-mode")" != fail ] || exit 71
cat "$base/inspect.json"
;;
*)
printf 'UNEXPECTED:%s\n' "$1" >> "$base/trace"
exit 72
;;
esac
