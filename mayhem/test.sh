#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# 1) Known-answer probe: real tengine parsers (request/status/chunked/URI/size/time/base64/mail/dubbo)
#    driven with fixed inputs; every printed value is compared with kat/expected.txt.
PROBE=/mayhem/kat_probe
NGINX="$SRC/objs-test/nginx"
for f in "$PROBE" "$NGINX"; do
    [ -x "$f" ] || { echo "missing $f: mayhem/build.sh should have built it" >&2; emit_ctrf "tengine-kat" 0 1 0; exit 1; }
done

passed=0 failed=0
check() {  # check <name> <expected> <actual>
    if [ "$2" == "$3" ]; then passed=$((passed + 1)); else failed=$((failed + 1)); echo "FAIL $1: expected [$2] got [$3]" >&2; fi
}

mapfile -t got < <("$PROBE" 2>/dev/null || true)
mapfile -t want < "$SRC/mayhem/kat/expected.txt"
check "kat:line-count" "${#want[@]}" "${#got[@]}"
for i in "${!want[@]}"; do
    check "kat:${want[$i]%%=*}" "${want[$i]}" "${got[$i]:-<missing>}"
done

# 2) The real server binary: version banner, config test (good and bad), and live requests.
check "nginx:version" "Tengine version: Tengine/3.2.0" "$("$NGINX" -v 2>&1 | head -1)"

work=$(mktemp -d)
trap 'kill "${srv:-0}" 2>/dev/null; rm -rf "$work"' EXIT
mkdir -p "$work/tmp" "$work/logs"
cp "$SRC/mayhem/kat/ok.conf" "$SRC/mayhem/kat/bad.conf" "$work/"

out=$("$NGINX" -t -p "$work" -c ok.conf 2>&1 || true)
check "nginx:conf-ok" "yes" "$(printf '%s' "$out" | grep -q 'test is successful' && echo yes || echo no)"
out=$("$NGINX" -t -p "$work" -c bad.conf 2>&1 || true)
check "nginx:conf-bad" "yes" "$(printf '%s' "$out" | grep -q 'unknown directive "no_such_directive"' && echo yes || echo no)"

"$NGINX" -p "$work" -c ok.conf >"$work/stdout" 2>&1 &
srv=$!
for _ in $(seq 1 50); do curl -s -o /dev/null http://127.0.0.1:18080/ping && break; sleep 0.1; done
check "nginx:ping" "pong tengine" "$(curl -s http://127.0.0.1:18080/ping || true)"
check "nginx:vars" "v=7-9" "$(curl -s 'http://127.0.0.1:18080/sum?a=7&b=9' || true)"
check "nginx:redirect" "302 /ping" "$(curl -s -o /dev/null -w '%{http_code} %{redirect_url}' http://127.0.0.1:18080/redir | sed 's#http://127.0.0.1:18080##' || true)"
check "nginx:chunked-parse" "404" "$(curl -s -o /dev/null -w '%{http_code}' -H 'Transfer-Encoding: chunked' --data-binary $'5\r\nhello\r\n0\r\n\r\n' http://127.0.0.1:18080/missing || true)"

emit_ctrf "tengine-kat" "$passed" "$failed" 0
