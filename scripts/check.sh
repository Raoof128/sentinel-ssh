#!/bin/sh
# SentinelSSH quality gate. Every gate must pass; the script stops at the first failure.
#
#   bash scripts/check.sh            full gate: static checks, Docker fixture, all tests, 100% line coverage
#   bash scripts/check.sh --quick    static checks and unit/contract tests only (no Docker, no coverage)
#   bash scripts/check.sh --large    full gate plus the 256 MiB download test (fixture built with LARGE=1)
#
# Coverage counts product code only (crates/sentinel-core, crates/sentinel-gateway). sentinel-testkit is test support.
set -eu
cd "$(dirname "$0")/.."

MODE=full
[ "${1:-}" = "--quick" ] && MODE=quick
[ "${1:-}" = "--large" ] && MODE=large

step() { printf '\n==> %s\n' "$1"; }
fail() { printf '\nFAIL: %s\n' "$1" >&2; exit 1; }

step "toolchain"
cargo --version
rustc --version

step "format (cargo fmt --check)"
cargo fmt --all --check || fail "run: cargo fmt --all"

step "lints (clippy, warnings are errors)"
cargo clippy -q --workspace --all-targets -- -D warnings || fail "clippy"

step "unsafe code is forbidden in every crate"
for f in crates/*/src/lib.rs crates/sentinel-gateway/src/main.rs; do
  grep -q '^#!\[forbid(unsafe_code)\]' "$f" || fail "$f lacks #![forbid(unsafe_code)]"
done
if grep -rn --include='*.rs' -E '\bunsafe\s*(\{|fn|impl)' crates/; then fail "unsafe block found"; fi

step "secret scan (tracked files)"
# Real private keys, cloud keys and tokens must never be committed. The fixture key and test identities live under
# target/ (ignored) and the only key-like fixture string is the explicit FAKE marker.
if git ls-files -z -- ':!scripts/check.sh' | xargs -0 grep -nIE \
  -e '-----BEGIN ([A-Z]+ )?PRIVATE KEY-----' \
  -e 'AKIA[0-9A-Z]{16}' \
  -e 'gh[pousr]_[A-Za-z0-9]{36,}' \
  -e 'xox[baprs]-[A-Za-z0-9-]{10,}' \
  -e 'sk-[A-Za-z0-9]{32,}' \
  2>/dev/null; then
  fail "possible secret in a tracked file"
fi
git ls-files | grep -E '(^|/)(id_[a-z0-9]+|.*\.pem|.*\.key)$' && fail "key file is tracked" || true

step "no NUL bytes or shell metacharacters smuggled into remote flag literals"
# Production code only: each file is scanned up to its #[cfg(test)] module (tests deliberately feed bad literals).
BAD_FLAGS=$(find crates/sentinel-gateway/src -name '*.rs' -exec awk '/^#\[cfg\(test\)\]/{exit} /\.flag\("[^"]*[ ;|&$`<>(){}]/{print FILENAME":"FNR": "$0}' {} \;)
[ -z "$BAD_FLAGS" ] || { printf '%s\n' "$BAD_FLAGS"; fail "unsafe flag literal"; }

step "tool contract docs are current"
bash scripts/gen-tool-contracts.sh >/dev/null
git diff --quiet -- docs/tool-contracts.md || fail "docs/tool-contracts.md is stale: commit the regenerated file"

if [ "$MODE" = "quick" ]; then
  step "tests (no fixture)"
  cargo test -q --workspace
  printf '\nOK (quick): static gates and unit/contract tests passed. Run without --quick for e2e and coverage.\n'
  exit 0
fi

step "Docker sshd fixture"
command -v docker >/dev/null || fail "docker is required for the full gate (use --quick to skip)"
docker info >/dev/null 2>&1 || fail "the Docker daemon is not running"
if [ "$MODE" = "large" ]; then LARGE=1 bash scripts/fixture-up.sh; else bash scripts/fixture-up.sh; fi
set -a
. target/fixture/fixture.env
set +a

step "all tests and 100% line coverage of product code"
IGNORED=""
[ "$MODE" = "large" ] && IGNORED="--include-ignored"
cargo llvm-cov --version >/dev/null 2>&1 || fail "cargo-llvm-cov is required: cargo install cargo-llvm-cov --locked; rustup component add llvm-tools-preview"
cargo llvm-cov clean --workspace >/dev/null 2>&1 || true
# shellcheck disable=SC2086
cargo llvm-cov --workspace \
  --ignore-filename-regex 'sentinel-testkit/' \
  --show-missing-lines \
  --fail-under-lines 100 \
  -- $IGNORED || fail "tests failed or line coverage is below 100% (uncovered lines are listed above)"

printf '\nOK: every gate passed (fmt, clippy, unsafe, secrets, docs, e2e fixture, tests, 100%% line coverage).\n'
