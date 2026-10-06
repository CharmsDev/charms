#!/usr/bin/env bash
# CharmsApply runs in the proxy's storage through delegatecall, so its layout must equal Charms's.
# An upgrade may only append to the v1 layout, so Charms's layout must start with storage-layout.json.
# Run with --write to accept a new snapshot after an append.
set -euo pipefail
cd "$(dirname "$0")/.."

layout() {
	forge inspect "$1" storageLayout --json |
		jq '[.storage[] | {label, slot, offset, type: (.type | gsub("t_struct\\((?<n>[^)]*)\\)[0-9]+_"; "t_struct(\(.n))_"))}]'
}

charms=$(layout src/Charms.sol:Charms)
applier=$(layout src/CharmsApply.sol:CharmsApply)

if [ "$charms" != "$applier" ]; then
	echo "CharmsApply and Charms storage layouts differ:" >&2
	diff <(echo "$charms") <(echo "$applier") >&2
	exit 1
fi

if [ "${1:-}" = "--write" ]; then
	echo "$charms" >storage-layout.json
	exit 0
fi

prefix=$(echo "$charms" | jq --slurpfile v1 storage-layout.json '.[0:($v1[0] | length)]')
if [ "$prefix" != "$(jq . storage-layout.json)" ]; then
	echo "Charms reorders, inserts, or retypes a v1 storage variable:" >&2
	diff <(jq . storage-layout.json) <(echo "$prefix") >&2
	exit 1
fi
echo "storage layout ok"
