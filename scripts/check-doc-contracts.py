#!/usr/bin/env python3
"""Check bilingual OpenSpec identities and the wire-profile registry tables."""

from itertools import groupby
from pathlib import Path
import re

SPECS = Path(__file__).resolve().parents[1] / "openspec" / "specs"

# Preserve protocol fields while allowing explanatory columns to be translated.
# Keys are the table headers in the English and Chinese specifications.
WIRE_TABLES = {
    ("Code", "Frame type", "Payload class"): ("frame types", 3),
    ("Bit", "Capability"): ("capabilities", 2),
    ("Name", "Value", "Applies to"): ("profile limits", 2),
    ("Code", "Name"): ("admission reasons", 2),
    ("编码", "名称"): ("admission reasons", 2),
    ("Code", "Name", "Use"): ("errors", 2),
}


def prose_lines(text):
    """Skip fenced examples when looking for spec headings and registry tables."""
    fence = ""
    for line in text.splitlines():
        if fence:
            marks = line.strip()
            if marks.startswith(fence) and not marks.strip(fence[0]):
                fence = ""
        else:
            match = re.match(r"^ {0,3}(`{3,}|~{3,})", line)
            if not match:
                yield line
                continue
            fence = match[1]
        yield ""


def requirements(document, text):
    """Include the owning requirement in each scenario identity."""
    identities = set()
    owner = None
    in_requirements = False
    for number, line in enumerate(prose_lines(text), 1):
        if line.startswith("## "):
            in_requirements = line == "## Requirements"
            owner = None
        if line.startswith("### Requirement: "):
            owner = line.removeprefix("### Requirement: ").strip()
            identity = (owner, "")
        elif line.startswith("#### Scenario: "):
            identity = (owner, line.removeprefix("#### Scenario: ").strip())
        else:
            if line.startswith("### "):
                owner = None
            continue
        if not in_requirements or not owner:
            raise ValueError(f"{document}:{number}: {line} has no valid parent")
        if identity in identities:
            raise ValueError(f"{document}:{number}: duplicate {identity}")
        identities.add(identity)
    if not identities:
        raise ValueError(f"{document}: missing requirement identities")
    return identities


def wire_registries(document, text):
    registries = {}
    for is_table, block in groupby(prose_lines(text), key=lambda line: line.startswith("|")):
        if not is_table:
            continue
        rows = [tuple(cell.strip() for cell in line.strip().strip("|").split("|")) for line in block]
        header = rows[0]
        if header not in WIRE_TABLES:
            continue
        name, fields = WIRE_TABLES[header]
        if name in registries or len(rows) < 3:
            raise ValueError(f"{document}: empty or repeated {name} table")
        if len(rows[1]) != len(header) or not all(re.fullmatch(r":?-+:?", cell) for cell in rows[1]):
            raise ValueError(f"{document}: malformed {name} table separator")
        values = {}
        for row in rows[2:]:
            if len(row) != len(header) or not all(row) or row[0] in values:
                raise ValueError(f"{document}: invalid or duplicate {name} row {row}")
            if name != "profile limits" and not re.fullmatch(r"[0-9]+", row[0]):
                raise ValueError(f"{document}: invalid {name} code {row[0]}")
            values[row[0]] = row[1:fields]
        registries[name] = set(values.items())
    for name, _ in WIRE_TABLES.values():
        if name not in registries:
            raise ValueError(f"{document}: missing {name} table")
    return registries


def compare(label, english, chinese):
    if english != chinese:
        english_only = sorted(english - chinese)
        chinese_only = sorted(chinese - english)
        raise ValueError(f"{label}: English only {english_only}, Chinese only {chinese_only}")


def main():
    if not (SPECS / "wire-profile").is_dir():
        raise ValueError(f"{SPECS}: missing wire-profile")
    capabilities = sorted(path for path in SPECS.iterdir() if path.is_dir())
    for capability in capabilities:
        en = capability / "spec.md"
        zh = capability / "spec.zh-CN.md"
        en_text = en.read_text(encoding="utf-8")
        zh_text = zh.read_text(encoding="utf-8")
        compare(capability.name, requirements(en, en_text), requirements(zh, zh_text))
        if capability.name == "wire-profile":
            en_tables = wire_registries(en, en_text)
            zh_tables = wire_registries(zh, zh_text)
            for name, values in en_tables.items():
                compare(f"wire-profile {name}", values, zh_tables[name])
    print(f"Checked requirement and scenario identities for {len(capabilities)} capability pairs and wire registries.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as error:
        raise SystemExit(str(error))
