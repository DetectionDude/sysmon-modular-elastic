#!/usr/bin/env sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
output_dir=${1:-"$repo_root/outputs"}
case "$output_dir" in
  /*) ;;
  *) output_dir="$PWD/$output_dir" ;;
esac

tool_path=
for candidate in \
  "$repo_root/tooling/sysmon-modular" \
  "$repo_root/tooling/sysmon-modular.exe"; do
  if [ -x "$candidate" ]; then
    tool_path=$candidate
    break
  fi
done

run_tool() {
  if [ -n "$tool_path" ]; then
    "$tool_path" "$@"
  elif command -v sysmon-modular >/dev/null 2>&1; then
    sysmon-modular "$@"
  elif command -v go >/dev/null 2>&1; then
    go -C "$repo_root/tooling" run ./cmd/sysmon-modular "$@"
  else
    printf '%s\n' 'sysmon-modular was not found. Download a release binary into tooling/ or install Go.' >&2
    exit 127
  fi
}

mkdir -p "$output_dir"

for profile in research complement; do
  output_path="$output_dir/sysmonconfig-elastic-$profile.xml"

  # A list entry that does not resolve is only a warning, which would silently drop a module.
  run_tool merge \
    --base-path "$repo_root" \
    --template "$repo_root/templates/sysmon_template.xml" \
    --include-list "$script_dir/$profile.txt" \
    --preserve-comments \
    --sysmon-version 15.21 \
    --unsupported exclude \
    --warnings-as-errors \
    --output "$output_path"

  run_tool validate \
    --path "$output_path" \
    --sysmon-version 15.21

  printf 'generated %s\n' "$output_path"
done
