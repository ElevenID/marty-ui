"""Embed the canonical hosting parser in the offline standalone bootstrap."""
import argparse
import ast
import io
from pathlib import Path
import tokenize

ROOT = Path(__file__).resolve().parent
BEGIN = "# BEGIN GENERATED HOSTING PARSER"
END = "# END GENERATED HOSTING PARSER"
NAMES = {
    "MAX_BYTES": "HOSTING_MAX", "MAX_ROOTS_BYTES": "HOSTING_ROOTS_MAX",
    "FIELDS": "HOSTING_FIELDS", "DIRECTORIES": "HOSTING_DIRECTORIES",
    **{name: "_hosting_" + name for name in
       ("exact", "decode", "origin", "terms", "validate", "from_bytes", "require_bytes")},
}


def render(source: str) -> str:
    lines = source.splitlines(keepends=True)
    sections = []
    for node in ast.parse(source).body:
        name = node.name if isinstance(node, ast.FunctionDef) else (
            node.targets[0].id if isinstance(node, ast.Assign)
            and isinstance(node.targets[0], ast.Name) else None)
        if name in NAMES:
            sections.append("".join(lines[node.lineno - 1:node.end_lineno]).rstrip())
    code = "\n\n\n".join(sections) + "\n"
    tokens = []
    previous = None
    for token in tokenize.generate_tokens(io.StringIO(code).readline):
        # Rename identifiers, never attributes such as bytes.decode or strings.
        if token.type == tokenize.NAME and previous != ".":
            token = token._replace(string=NAMES.get(token.string, token.string))
        tokens.append(token)
        if token.type not in (tokenize.NL, tokenize.NEWLINE, tokenize.COMMENT,
                              tokenize.INDENT, tokenize.DEDENT):
            previous = token.string
    return (BEGIN + "\n# Source: installer_candidate_hosting.py; regenerate with "
            "generate_bootstrap_hosting.py.\n" + tokenize.untokenize(tokens) + END)


def generated_bootstrap(source: str, bootstrap: str) -> str:
    before, rest = bootstrap.split(BEGIN, 1)
    _, after = rest.split(END, 1)
    return before + render(source) + after


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    target = ROOT / "installer_candidate_public_bootstrap.py"
    current = target.read_text(encoding="utf-8")
    expected = generated_bootstrap(
        (ROOT / "installer_candidate_hosting.py").read_text(encoding="utf-8"), current)
    if args.check:
        if current != expected:
            parser.exit(1, "Standalone hosting parser is stale; run generate_bootstrap_hosting.py\n")
    else:
        target.write_text(expected, encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
