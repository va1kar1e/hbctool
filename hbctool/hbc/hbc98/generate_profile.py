"""Generate the v98 opcode table from the pinned Meta BytecodeList.def.

Run: python -m hbctool.hbc.hbc98.generate_profile
The generator deliberately accepts only the directive forms used by the pinned
release. A new Hermes release must be reviewed instead of silently guessed.
"""

import hashlib
import json
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
SOURCE = HERE / "reference" / "BytecodeList.def"
OUTPUT = HERE / "opcode.json"
COMMIT = "becc964bd16002569bf74c4d8c190cfd2ad38985"


def generate():
    source = SOURCE.read_text(encoding="utf-8")
    opcodes = []
    meanings = {}
    for line in source.splitlines():
        match = re.match(r"^(DEFINE_OPCODE_([0-6])|DEFINE_JUMP_([123])|OPERAND_(STRING|FUNCTION|BIGINT)_ID)\(([^)]*)\)", line)
        if not match:
            continue
        directive, count, jump, meaning, arguments = match.groups()
        args = [arg.strip() for arg in arguments.split(",")]
        if count is not None:
            assert len(args) == int(count) + 1, line
            opcodes.append({"name": args[0], "operands": args[1:]})
        elif jump is not None:
            operands = ["Reg8"] * (int(jump) - 1)
            opcodes.append({"name": args[0], "operands": ["Addr8"] + operands})
            opcodes.append({"name": args[0] + "Long", "operands": ["Addr32"] + operands})
        else:
            meanings.setdefault(args[0], {})[int(args[1]) - 1] = meaning.lower()
    for opcode, item in enumerate(opcodes):
        item["opcode"] = opcode
        item["meanings"] = {str(k): v for k, v in meanings.get(item["name"], {}).items()}
        assert opcode < 256, "opcode table exceeds one byte"
    result = {
        "profile": "hermes-v250829098.0.10",
        "hermes_commit": COMMIT,
        "source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        "opcodes": opcodes,
    }
    return result


def main():
    result = generate()
    OUTPUT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"Generated {len(result['opcodes'])} v98 opcodes from {result['source_sha256']}")


if __name__ == "__main__":
    main()
