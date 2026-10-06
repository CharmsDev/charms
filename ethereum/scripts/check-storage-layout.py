#!/usr/bin/env python3
"""Fail when the proxy's storage layout changes in a way an upgrade cannot survive.

CharmsApply runs in the proxy's storage through delegatecall, so its layout, struct members
included, must equal Charms's. Against the committed v1 snapshot, an upgrade may append
variables after `__gap`, take slots from the gap while keeping its end slot, and append members
to a struct. It may not move, retype, or delete a v1 variable or struct member.

Run with --write to accept a new snapshot.
"""

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SNAPSHOT = ROOT / "storage-layout.json"
AST_ID = re.compile(r"(t_(?:struct|enum|contract|userDefinedValueType)\([^)]*\))\d+")


def normalize(type_id):
    return AST_ID.sub(r"\1", type_id)


def entry(item):
    return {
        "label": item["label"],
        "slot": int(item["slot"]),
        "offset": item["offset"],
        "type": normalize(item["type"]),
    }


def layout(contract):
    inspect = subprocess.run(
        ["forge", "inspect", contract, "storageLayout", "--json"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    if inspect.returncode != 0:
        sys.exit(f"forge inspect {contract} failed:\n{inspect.stderr}")
    raw = json.loads(inspect.stdout)
    types = {}
    for type_id, info in raw["types"].items():
        shaped = {
            key: normalize(value) if key in ("base", "key", "value") else value
            for key, value in info.items()
            if key != "members"
        }
        if "members" in info:
            shaped["members"] = [entry(member) for member in info["members"]]
        types[normalize(type_id)] = shaped
    return {"storage": [entry(item) for item in raw["storage"]], "types": types}


def slots(layout_, item):
    return int(layout_["types"][item["type"]]["numberOfBytes"]) // 32


def upgrade_errors(v1, current):
    errors = []
    now = {item["label"]: item for item in current["storage"]}
    gap_types = {item["type"] for item in v1["storage"] if item["label"] == "__gap"}
    for old in v1["storage"]:
        new = now.get(old["label"])
        if old["label"] == "__gap":
            if new is not None and new["slot"] + slots(current, new) != old["slot"] + slots(
                v1, old
            ):
                errors.append("__gap no longer ends at its v1 slot")
        elif new != old:
            errors.append(f"v1 variable {old['label']} moved, changed type, or is gone")
    for type_id, old in v1["types"].items():
        if type_id in gap_types:
            continue
        new = current["types"].get(type_id)
        if new is None:
            errors.append(f"v1 type {type_id} is gone")
            continue
        if "members" in old:
            if new.get("members", [])[: len(old["members"])] != old["members"]:
                errors.append(f"{old['label']} moved, changed, or removed a member")
            old, new = (
                {k: v for k, v in t.items() if k not in ("members", "numberOfBytes")}
                for t in (old, new)
            )
        if new != old:
            errors.append(f"v1 type {type_id} changed")
    return errors


def main():
    charms = layout("src/Charms.sol:Charms")
    applier = layout("src/CharmsApply.sol:CharmsApply")
    if charms != applier:
        sys.exit("CharmsApply and Charms storage layouts differ")
    if sys.argv[1:] == ["--write"]:
        SNAPSHOT.write_text(json.dumps(charms, indent=2, sort_keys=True) + "\n")
        return
    errors = upgrade_errors(json.loads(SNAPSHOT.read_text()), charms)
    if errors:
        sys.exit("\n".join(errors))
    print("storage layout ok")


if __name__ == "__main__":
    main()
