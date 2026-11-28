#!/usr/bin/env python3
"""Validate shipped examples and complete YAML examples in the Markdown documentation."""

import json
import re
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLI = ["cargo", "run", "--quiet", "--locked", "-p", "pathchordctl", "--"]
EXAMPLE = re.compile(
    r"^(?P<fence>`{3,}|~{3,})yaml[ \t]*\n# pathchord-check: (?P<role>ingress|egress)\n"
    r"(?P<yaml>.*?)^(?P=fence)[ \t]*$",
    re.MULTILINE | re.DOTALL,
)


def validate(role, source, label):
    result = subprocess.run(
        [*CLI, "--config", source, "config", "validate", "--role", role],
        cwd=ROOT, capture_output=True, text=True,
    )
    if result.returncode:
        raise SystemExit(f"{label}: {result.stderr.strip() or result.stdout.strip()}")
    print(f"Validated {label} ({role})")


def main():
    with tempfile.TemporaryDirectory() as directory:
        temporary = Path(directory)
        output = subprocess.check_output(
            [*CLI, "-o", "json", "keygen", "--identity-file", temporary / "identity.json"],
            cwd=ROOT, text=True,
        )
        public_key = json.loads(output)["public_key"]
        scratch = temporary / "example.yaml"
        for source in sorted((ROOT / "examples").glob("*.yaml")):
            role = source.stem.split("-", 1)[0]
            yaml = source.read_text(encoding="utf-8")
            if "REPLACE_WITH_EGRESS_PUBLIC_KEY" in yaml:
                scratch.write_text(yaml.replace("REPLACE_WITH_EGRESS_PUBLIC_KEY", public_key))
                validate(role, scratch, source.relative_to(ROOT))
            else:
                validate(role, source, source.relative_to(ROOT))

        documents = sorted([
            *ROOT.glob("README*.md"),
            *ROOT.glob("docs/**/*.md"),
            *ROOT.glob("openspec/specs/**/*.md"),
        ])
        for document in documents:
            markdown = document.read_text(encoding="utf-8")
            examples = list(EXAMPLE.finditer(markdown))
            if len(examples) != len(re.findall(r"^# pathchord-check:", markdown, re.MULTILINE)):
                raise SystemExit(f"{document}: invalid example marker or YAML fence")
            if document.parent == ROOT / "openspec/specs/configuration" and not examples:
                raise SystemExit(f"{document}: missing complete configuration example")
            for example in examples:
                line = markdown.count("\n", 0, example.start()) + 1
                scratch.write_text(example["yaml"].replace("<curve25519-public-key>", public_key))
                validate(example["role"], scratch, f"{document.relative_to(ROOT)}:{line}")


if __name__ == "__main__":
    main()
