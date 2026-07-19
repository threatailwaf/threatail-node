#!/usr/bin/env bash
# Pre-flight checks before making threatail-node public.
# Run from the repository root:  bash preflight.sh
#
# Nothing here modifies your code. It only reports.
# Exit code 0 means you are clear to publish.

set -uo pipefail
FAIL=0
WARN=0

ok()   { printf '  \033[32m✓\033[0m %s\n' "$1"; }
bad()  { printf '  \033[31m✗\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
warn() { printf '  \033[33m!\033[0m %s\n' "$1"; WARN=$((WARN+1)); }
head_() { printf '\n\033[1m%s\033[0m\n' "$1"; }

[ -f Cargo.toml ] || { echo "Run this from the repository root."; exit 1; }

# ─────────────────────────────────────────────────────────────
head_ "1. Licence"
if [ ! -f LICENSE ]; then
  bad "LICENSE is missing — without it the code is not open source"
elif grep -qi 'PLACEHOLDER' LICENSE; then
  bad "LICENSE is still the placeholder. Fetch it:
      curl -o LICENSE https://www.apache.org/licenses/LICENSE-2.0.txt"
elif ! grep -qi 'Apache License' LICENSE; then
  warn "LICENSE exists but does not look like Apache-2.0 — check it is what you intend"
else
  ok "LICENSE present ($(wc -l < LICENSE) lines)"
fi

if grep -q '^license *=' Cargo.toml; then
  ok "Cargo.toml declares $(grep '^license *=' Cargo.toml | head -1 | tr -d ' ')"
else
  bad 'Cargo.toml has no license field. Add:  license = "Apache-2.0"'
fi

# ─────────────────────────────────────────────────────────────
head_ "2. Version consistency"
CT=$(grep -m1 '^version *=' Cargo.toml | sed 's/.*"\(.*\)".*/\1/')
CL=$(awk '/^name = "threatail-node"$/{getline; print}' Cargo.lock | sed 's/.*"\(.*\)".*/\1/')
if [ -z "$CT" ]; then
  bad "no version in Cargo.toml"
elif [ "$CT" = "$CL" ]; then
  ok "version $CT (Cargo.toml and Cargo.lock agree)"
else
  bad "version mismatch: Cargo.toml=$CT, Cargo.lock=$CL — run 'cargo check' to resync"
fi
if grep -q 'cloud data plane\|Threatail Cloud —' Cargo.toml; then
  warn "Cargo.toml description still describes the cloud agent, not the standalone node"
fi

# ─────────────────────────────────────────────────────────────
head_ "3. Placeholders"
PH=$(grep -rl 'OWNER/threatail-node' --include='*.md' --include='*.yaml' \
        --include='*.yml' --include='Dockerfile' . 2>/dev/null)
if [ -n "$PH" ]; then
  bad "OWNER placeholder still present in:"; echo "$PH" | sed 's/^/        /'
else
  ok "no OWNER placeholders left"
fi

# ─────────────────────────────────────────────────────────────
head_ "4. Files that must never be committed"
LEAKY=$(git ls-files 2>/dev/null | grep -E '(^|/)config\.json$|\.mmdb$|\.pem$|\.key$|\.crt$|\.p12$|(^|/)model\.json$|\.jsonl$|__pycache__' || true)
if [ -n "$LEAKY" ]; then
  bad "these are tracked by git and should not be:"; echo "$LEAKY" | sed 's/^/        /'
else
  ok "no config, certificates, models or datasets tracked"
fi

if [ -f src/default_model.json ]; then
  if grep -q '"trees":\[\]' src/default_model.json; then
    ok "src/default_model.json is the empty placeholder (as intended)"
  else
    bad "src/default_model.json contains a REAL model — it must not be published"
  fi
fi

# ─────────────────────────────────────────────────────────────
head_ "5. Secrets"
if command -v gitleaks >/dev/null 2>&1; then
  if gitleaks detect -s . --no-banner >/dev/null 2>&1; then
    ok "gitleaks: no leaks found"
  else
    bad "gitleaks found something — inspect with:  gitleaks detect -s . -v"
  fi
else
  warn "gitleaks not installed — skipping (install it, this check matters most)"
fi

# ─────────────────────────────────────────────────────────────
head_ "6. Build, lint, tests"
if ! command -v cargo >/dev/null 2>&1; then
  bad "cargo not found"
else
  RUSTV=$(rustc --version | awk '{print $2}')
  ok "toolchain $RUSTV"
  printf '  … cargo clippy (this takes a while)\n'
  if cargo clippy --all-targets -- -D warnings >/tmp/pf_clippy.log 2>&1; then
    ok "clippy clean with -D warnings"
  else
    bad "clippy failed ($(grep -c '^error' /tmp/pf_clippy.log) errors) — see /tmp/pf_clippy.log"
  fi
  printf '  … cargo test\n'
  TESTS_OK=0
  if cargo test --all >/tmp/pf_test.log 2>&1; then
    ok "tests pass"; TESTS_OK=1
  else
    bad "tests failed — see /tmp/pf_test.log"
  fi
  # The security-relevant serde defaults. Only meaningful once the crate builds:
  # if compilation is broken, a failure here says nothing about the defaults.
  if grep -q 'default_tests' src/config.rs 2>/dev/null; then
    if [ "$TESTS_OK" -eq 1 ]; then
      if cargo test default_tests >/tmp/pf_def.log 2>&1; then
        ok "serde defaults applied (tail inspection and oversized signal are live)"
      else
        bad "DEFAULTS NOT APPLIED — a protection is silently off. See /tmp/pf_def.log"
      fi
    else
      warn "defaults check skipped — fix the build first, then re-run"
    fi
  fi
fi

# ─────────────────────────────────────────────────────────────
head_ "7. Docker"
if command -v docker >/dev/null 2>&1; then
  printf '  … docker build\n'
  if docker build -q -t threatail-node:preflight . >/tmp/pf_docker.log 2>&1; then
    ok "image builds"
  else
    bad "docker build failed — see /tmp/pf_docker.log"
  fi
else
  warn "docker not found — skipping image build"
fi

# ─────────────────────────────────────────────────────────────
head_ "8. Git state"
if git rev-parse --git-dir >/dev/null 2>&1; then
  N=$(git rev-list --count HEAD 2>/dev/null || echo 0)
  if [ "$N" -le 1 ]; then
    ok "$N commit — clean history, nothing from the private repo can leak"
  else
    warn "$N commits. Make sure none carry cloud code or secrets:  git log --stat"
  fi
  [ -n "$(git status --porcelain)" ] && warn "uncommitted changes — commit before pushing" \
                                     || ok "working tree clean"
else
  warn "not a git repository yet — run: git init -b main && git add -A && git commit -m 'Initial public release'"
fi

# ─────────────────────────────────────────────────────────────
printf '\n\033[1m─────────────────────────────\033[0m\n'
if [ "$FAIL" -eq 0 ]; then
  printf '\033[32mReady to publish\033[0m  (%d warnings)\n' "$WARN"
  exit 0
else
  printf '\033[31m%d blocker(s), %d warning(s) — do not publish yet\033[0m\n' "$FAIL" "$WARN"
  exit 1
fi
