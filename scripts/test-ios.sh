#!/usr/bin/env bash
# Build the iOS app once, then run each test plan without rebuilding.
# Usage: scripts/test-ios.sh build|unit [Class...]|ui [Class...]|tour [en|fr|ax3]|all|--help
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

apple="$root/apple"
derived="$apple/build/DerivedData"
xcfw="$root/target/apple/BarkingFFI.xcframework"
sim_name="Barking iPhone"

fail() { echo "error: $*" >&2; exit 1; }

usage() {
  cat <<'EOF'
Usage: scripts/test-ios.sh build|unit [Classe...]|ui [Classe...]|tour [en|fr|ax3]|all|--help

  build   xcodegen and XCFramework if stale, then build-for-testing
  unit    plan Unit (BarkingTests), optionally restricted to the given classes
  ui      plan UI (BarkingUITests), 3 parallel clones, optionally restricted to classes
  tour    TourUITests with BARKING_TOUR=1 (en, fr or ax3), result in apple/build/tour-<lang>.xcresult
  all     build, unit, ui, tour en

Règle pour les agents.
Pendant un lot :
- Rust : cargo nextest run -p <crate> sur la crate touchée, profil par défaut ;
- iOS : scripts/test-ios.sh build, puis scripts/test-ios.sh unit <Classes touchées> et scripts/test-ios.sh ui <Classes touchées> ;
- en fin de lot, une seule fois : scripts/check.sh --full et scripts/test-ios.sh all.
EOF
}

# Run a named step and print its duration.
step() {
  local name="$1"; shift
  local start=$SECONDS
  "$@"
  echo "==> $name ($((SECONDS - start)) s)"
}

sim_udid=""
ensure_sim() {
  [ -n "$sim_udid" ] && return 0
  local info
  info="$(xcrun simctl list devices -j | python3 -c '
import json, sys
name = sys.argv[1]
for rt, devs in json.load(sys.stdin)["devices"].items():
    for d in devs:
        if d["name"] == name and d.get("isAvailable"):
            print(d["udid"]); sys.exit(0)
' "$sim_name")"
  if [ -z "$info" ]; then
    local pick
    pick="$(python3 - "$sim_name" <<'PY'
import json, re, subprocess, sys
def sj(*a): return json.loads(subprocess.check_output(["xcrun", "simctl", "list", "-j", *a]))
types = [t for t in sj("devicetypes")["devicetypes"] if t["identifier"].startswith("com.apple.CoreSimulator.SimDeviceType.iPhone-")]
def gen(t):
    m = re.search(r"iPhone-(\d+)", t["identifier"])
    return int(m.group(1)) if m else -1
# Highest generation wins; simctl lists newest first, so ties keep list order.
best = sorted(types, key=lambda t: -gen(t))[0]
rts = [r for r in sj("runtimes")["runtimes"] if r.get("isAvailable") and r["identifier"].startswith("com.apple.CoreSimulator.SimRuntime.iOS-")]
def ver(r): return tuple(int(x) for x in r["version"].split("."))
# Newest version; among equals prefer the plain runtime (shortest identifier).
rt = sorted(rts, key=lambda r: (tuple(-v for v in ver(r)), len(r["identifier"])))[0]
print(best["identifier"], rt["identifier"])
PY
)"
    # shellcheck disable=SC2086
    info="$(xcrun simctl create "$sim_name" $pick)"
  fi
  sim_udid="$info"
  xcrun simctl bootstatus "$sim_udid" -b >/dev/null
}

freshness() {
  local proj="$apple/Barking.xcodeproj/project.pbxproj"
  if [ ! -f "$proj" ] || [ "$apple/project.yml" -nt "$proj" ]; then
    step "xcodegen" bash -c "cd '$apple' && xcodegen generate >/dev/null"
  fi
  if [ ! -d "$xcfw" ] || [ -n "$(find "$root/crates" "$root/Cargo.lock" -type f -not -path '*/target/*' -newer "$xcfw" -print -quit)" ]; then
    step "build-xcframework" "$root/scripts/build-xcframework.sh" --sim-only
  fi
}

xb() { xcodebuild -project "$apple/Barking.xcodeproj" -scheme Barking -derivedDataPath "$derived" -destination "platform=iOS Simulator,id=$sim_udid" "$@"; }

do_build() {
  freshness
  ensure_sim
  step "build" xb build-for-testing
}

# only_args <Target> <Class...> fills the global "only" array.
only=()
only_args() {
  local target="$1"; shift
  only=()
  for c in "$@"; do only+=(-only-testing:"$target/$c"); done
}

do_unit() {
  ensure_sim
  only_args BarkingTests "$@"
  step "unit" xb test-without-building -testPlan Unit -parallel-testing-enabled NO ${only[@]+"${only[@]}"}
}

do_ui() {
  ensure_sim
  only_args BarkingUITests "$@"
  step "ui" xb test-without-building -testPlan UI -parallel-testing-enabled YES -parallel-testing-worker-count 3 ${only[@]+"${only[@]}"}
}

do_tour() {
  local lang="${1:-en}"
  case "$lang" in en|fr|ax3) ;; *) fail "tour language must be en, fr or ax3" ;; esac
  ensure_sim
  export TEST_RUNNER_BARKING_TOUR=1
  [ "$lang" = fr ] && export TEST_RUNNER_BARKING_TOUR_LANG=fr
  [ "$lang" = ax3 ] && export TEST_RUNNER_BARKING_TOUR_SIZE=UICTContentSizeCategoryAccessibilityL
  local bundle="$apple/build/tour-$lang.xcresult"
  rm -rf "$bundle"
  step "tour $lang" xb test-without-building -testPlan UI -parallel-testing-enabled NO -only-testing:BarkingUITests/TourUITests -resultBundlePath "$bundle"
}

cmd="${1:-}"; [ $# -gt 0 ] && shift
case "$cmd" in
  build) do_build ;;
  unit) do_unit "$@" ;;
  ui) do_ui "$@" ;;
  tour) do_tour "$@" ;;
  all) do_build; do_unit; do_ui; do_tour en ;;
  -h|--help|help) usage ;;
  *) usage >&2; exit 2 ;;
esac
