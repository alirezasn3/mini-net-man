#!/bin/sh
# Runs inside the privileged test container (see `make integration`).
# Every test gets its own network namespace, so they can't affect each other
# or the container.
set -u
cd /src
go test -c -tags integration -o /tmp/it.test ./internal/integration || exit 1

pattern="${1:-.*}"
fail=0
for t in $(/tmp/it.test -test.list "$pattern"); do
  if out=$(unshare -n /tmp/it.test -test.run "^$t\$" -test.v 2>&1); then
    echo "PASS  $t"
  else
    echo "FAIL  $t"
    echo "$out" | sed 's/^/      /'
    fail=1
  fi
done
exit $fail
