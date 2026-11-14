#!/usr/bin/env bash
# ===========================================================================
#  build-fpc.sh - compile AND run the horse-session conformance test with
#  Free Pascal (Linux x86_64). A gate: exit 0 only when the program builds
#  and every check passes.
#
#  Usage:
#    tests/build-fpc.sh
#
#  Environment (all optional):
#    FPC        compiler                 default /usr/bin/fpc
#    HORSE_DIR  Horse checkout           default <repos>/horse
#    OUT        output directory         default a fresh mktemp dir
#    FPC_UNITS  the compiler's unit tree (the dir holding rtl/), default
#               derived from FPC's version and target
#    NO_RUN     set to 1 to build only
#
#  Same -n / -B / -Fu$FPC_UNITS/* discipline as sibling scripts in
#  horse-ai / horse-jsonrpc: skip the distro fpc.cfg, rebuild every unit
#  from source, take the RTL from the compiler's own tree.
# ===========================================================================
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$HERE/.." && pwd)
REPOS=$(dirname "$REPO_ROOT")

HORSE_DIR=${HORSE_DIR:-$REPOS/horse}
FPC=${FPC:-/usr/bin/fpc}
OUT=${OUT:-$(mktemp -d /tmp/horse-session-fpc.XXXXXX)}
PROGRAM="$REPO_ROOT/tests/HorseSessionTests.dpr"
NO_RUN=${NO_RUN:-0}

fail() { echo "VOID - $1"; exit 2; }

[ -x "$FPC" ] || fail "no compiler at $FPC (set FPC=...)"
[ -d "$REPO_ROOT/src" ] || fail "no package src at $REPO_ROOT/src"
[ -f "$HORSE_DIR/src/Horse.pas" ] || fail "no Horse at $HORSE_DIR (set HORSE_DIR=...)"
[ -f "$PROGRAM" ] || fail "no program $PROGRAM"

FPC_VER=$("$FPC" -iV)
FPC_TARGET="$("$FPC" -iTP)-$("$FPC" -iTO)"
if [ -z "${FPC_UNITS:-}" ]; then
  for c in "$(dirname "$(dirname "$FPC")")/lib/fpc/$FPC_VER/units/$FPC_TARGET" \
           "/usr/lib/x86_64-linux-gnu/fpc/$FPC_VER/units/$FPC_TARGET" \
           "/usr/lib/fpc/$FPC_VER/units/$FPC_TARGET"; do
    if [ -f "$c/rtl/system.ppu" ]; then FPC_UNITS=$c; break; fi
  done
fi
[ -n "${FPC_UNITS:-}" ] && [ -f "$FPC_UNITS/rtl/system.ppu" ] || \
  fail "no RTL for fpc $FPC_VER ($FPC_TARGET) - set FPC_UNITS to the directory holding rtl/"

LIB_PATHS=()
for d in /usr/lib/x86_64-linux-gnu /lib/x86_64-linux-gnu; do
  [ -d "$d" ] && LIB_PATHS+=("-Fl$d")
done
mkdir -p "$OUT" || fail "cannot create $OUT"

describe() { git -C "$1" describe --tags --always --dirty 2>/dev/null || echo "(not a git checkout)"; }

echo "=== horse-session FPC build ==="
echo "fpc:     $FPC  $FPC_VER ($FPC_TARGET)"
echo "rtl:     $FPC_UNITS"
echo "package: $REPO_ROOT  $(describe "$REPO_ROOT")"
echo "horse:   $HORSE_DIR  $(describe "$HORSE_DIR")"
echo "program: $PROGRAM"
echo "out:     $OUT"
echo

"$FPC" -n -B -Mdelphi -vew \
  "-Fu$FPC_UNITS/*" \
  "-Fu$HORSE_DIR/src" "-Fu$REPO_ROOT/src" \
  "${LIB_PATHS[@]}" \
  "-FU$OUT" "-FE$OUT" \
  "$PROGRAM" 2>&1 | tee "$OUT/build.log"
RC=${PIPESTATUS[0]}

echo
echo "==========================================================================="
if [ "$RC" -ne 0 ]; then
  echo " BUILD FAILED, fpc exit $RC   (log: $OUT/build.log)"
  echo " Read the FIRST error above; later ones are often its cascade."
  echo "==========================================================================="
  exit "$RC"
fi
echo " BUILD OK   (log: $OUT/build.log)"
echo "==========================================================================="

EXE="$OUT/$(basename "${PROGRAM%.*}")"
if [ "$NO_RUN" = "1" ] || [ ! -x "$EXE" ]; then
  echo "(not run)"
  exit 0
fi

echo
echo "=== run ==="
"$EXE" | tee "$OUT/run.log"
RC=${PIPESTATUS[0]}
echo
if [ "$RC" -eq 0 ]; then
  echo " TESTS PASSED   (log: $OUT/run.log)"
else
  echo " TESTS FAILED, exit $RC   (log: $OUT/run.log)"
fi
exit "$RC"
