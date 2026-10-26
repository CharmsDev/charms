#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

"$root/charms-spell-checker/build-guests.sh"

paths=(
  src/bin/charms-spell-checker
  src/bin/charms-proof-wrapper
  src/bin/charms-spell-checker-vk.bin
  src/bin/charms-proof-wrapper-vk.bin
  charms-proof-wrapper/src/lib.rs
  charms-lib/src/lib.rs
)

set +e
git diff --quiet HEAD -- "${paths[@]}"
status=$?
set -e

if [[ "$status" -eq 0 ]]; then
  dirty=$(git status --porcelain --untracked-files=all)
  if [[ -n "$dirty" ]]; then
    printf '%s\n' "$dirty" >&2
    echo "guest rebuild changed other paths" >&2
    exit 1
  fi
  exit 0
fi
if [[ "$status" -ne 1 ]]; then
  echo "git diff --quiet HEAD failed with status ${status}" >&2
  exit "$status"
fi

git diff --stat HEAD -- "${paths[@]}" || true
git diff -- HEAD -- charms-proof-wrapper/src/lib.rs charms-lib/src/lib.rs || true
for path in "${paths[@]}"; do
  printf 'HEAD %s %s\n' "$(git rev-parse "HEAD:${path}")" "$path"
  printf 'worktree %s %s\n' "$(git hash-object "$path")" "$path"
done
echo "guest rebuild changed committed outputs" >&2
exit 1
