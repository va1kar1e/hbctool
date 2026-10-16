"""Editable v98 HASM format with an immutable original bytecode snapshot."""

import hashlib
import json
from pathlib import Path
import re
import struct

from .core import BY_NAME, HBC98, HBC98Error, OPCODE_PROFILE, TYPES, require

FORMAT = 2
HEADER = "metadata.json"
STRINGS = "string.json"
INSTRUCTIONS = "instruction.hasm"
ORIGINAL = "original.hbc"
SWITCHES = "switch_tables.json"
SIDE_TABLE_OPS = ("UIntSwitchImm", "StringSwitchImm", "NewArrayWithBuffer",
                  "NewArrayWithBufferLong", "NewObjectWithBuffer",
                  "NewObjectWithBufferLong", "NewObjectWithBufferAndParent",
                  "CreateRegExp", "CacheNewObject")


def _json(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def dump(hbc, path):
    path = Path(path)
    require(not path.exists(), "Output HASM directory already exists: %s" % path)
    path.mkdir(parents=True)
    (path / ORIGINAL).write_bytes(hbc.data)
    metadata = {"formatVersion": FORMAT, "profile": hbc.profile,
                "hermesCommit": OPCODE_PROFILE["hermes_commit"],
                "opcodeSourceSha256": OPCODE_PROFILE["source_sha256"],
                "inputSha256": hbc.raw_sha256(), "version": 98,
                "header": hbc.header, "sections": hbc.sections,
                "functionCount": hbc.getFunctionCount(), "stringCount": hbc.getStringCount()}
    with (path / STRINGS).open("w", encoding="utf-8") as stream:
        stream.write("[\n")
        for sid, value in enumerate(hbc.strings):
            stream.write(("," if sid else "") + _json({"id": sid,
                             "isUTF16": hbc.string_entries[sid]["utf16"],
                             "value": value}) + "\n")
        stream.write("]\n")
    with (path / INSTRUCTIONS).open("w", encoding="utf-8", newline="\n") as stream:
        switches = []
        for fid, fh in enumerate(hbc.functions):
            instructions = hbc.validate_function(fid)
            stream.write("@function " + _json(fh) + "\n")
            for offset, definition, values, end in instructions:
                switch = hbc.switch_table(fid, (offset, definition, values, end))
                if switch:
                    switches.append(switch)
                operands = []
                for typ, value in zip(definition["operands"], values):
                    if typ == "Double":
                        operands.append("Double:0x%016x" % value)
                    else:
                        operands.append("%s:%d" % (typ, value))
                stream.write("%08x %s%s\n" % (offset, definition["name"],
                                                " " + " ".join(operands) if operands else ""))
            stream.write("@end\n")
    switch_content = _json(switches) + "\n"
    (path / SWITCHES).write_text(switch_content, encoding="utf-8")
    metadata["switchTablesSha256"] = hashlib.sha256(switch_content.encode("utf-8")).hexdigest()
    (path / HEADER).write_text(_json(metadata) + "\n", encoding="utf-8")


def _parse_instruction(line, fid, expected, old, starts, hbc):
    offset, definition, old_values, end = old
    fields = line.strip().split()
    require(len(fields) >= 2 and re.fullmatch(r"[0-9a-f]{8}", fields[0]),
            "Function %d offset 0x%x: malformed HASM instruction" % (fid, offset))
    require(int(fields[0], 16) == offset,
            "Function %d offset 0x%x: instruction offset changed" % (fid, offset))
    new = BY_NAME.get(fields[1])
    require(new is not None, "Function %d offset 0x%x: unknown opcode %s" % (fid, offset, fields[1]))
    require(new["operands"] == definition["operands"],
            "Function %d offset 0x%x: operand layout changed" % (fid, offset))
    require(new["meanings"] == definition["meanings"],
            "Function %d offset 0x%x: reference meaning changed" % (fid, offset))
    require(len(fields) == 2 + len(new["operands"]),
            "Function %d offset 0x%x: operand count changed" % (fid, offset))
    values = []
    for i, typ in enumerate(new["operands"]):
        left, sep, right = fields[2 + i].partition(":")
        require(sep and left == typ, "Function %d offset 0x%x: operand type changed" % (fid, offset))
        try:
            if typ == "Double":
                require(bool(re.fullmatch(r"0x[0-9a-fA-F]{16}", right)),
                        "Function %d offset 0x%x: Double must be 64-bit hex" % (fid, offset))
                value = int(right, 16)
            else:
                require(bool(re.fullmatch(r"-?(0|[1-9][0-9]*)", right)),
                        "Function %d offset 0x%x: invalid operand" % (fid, offset))
                value = int(right)
            struct.pack("<" + TYPES[typ], value)
        except struct.error as exc:
            raise HBC98Error("Function %d offset 0x%x: operand outside %s range" %
                             (fid, offset, typ)) from exc
        values.append(value)
    changed = new["opcode"] != definition["opcode"] or values != old_values
    if changed:
        require(definition["name"] not in SIDE_TABLE_OPS and new["name"] not in SIDE_TABLE_OPS,
                "Function %d offset 0x%x: side-table instruction edit unsupported" % (fid, offset))
        for i, (typ, value) in enumerate(zip(new["operands"], values)):
            meaning = new["meanings"].get(str(i))
            count = {"string": hbc.getStringCount(), "function": hbc.getFunctionCount(),
                     "bigint": hbc.header["bigIntCount"]}.get(meaning)
            if count is not None:
                require(value < count, "Function %d offset 0x%x: %s ID out of range" %
                        (fid, offset, meaning))
            if typ in ("Addr8", "Addr32"):
                require(offset + value in starts,
                        "Function %d offset 0x%x: branch target invalid" % (fid, offset))
            if typ in ("Reg8", "Reg32") and value != old_values[i]:
                require(value < hbc.functions[fid]["frameSize"],
                        "Function %d offset 0x%x: register outside frame" % (fid, offset))
    encoded = bytes([new["opcode"]]) + b"".join(
        struct.pack("<" + TYPES[typ], value) for typ, value in zip(new["operands"], values))
    require(len(encoded) == end - offset,
            "Function %d offset 0x%x: instruction size changed" % (fid, offset))
    return encoded if changed else None


def _patch_strings(hbc, content, output):
    entries = json.loads(content)
    require(isinstance(entries, list) and len(entries) == hbc.getStringCount(),
            "String table count changed")
    spans = sorted((e["offset"], e["offset"] + e["bytes"], sid)
                   for sid, e in enumerate(hbc.string_entries) if e["bytes"])
    for sid, item in enumerate(entries):
        require(isinstance(item, dict) and set(item) == {"id", "isUTF16", "value"}
                and item["id"] == sid and item["isUTF16"] is hbc.string_entries[sid]["utf16"]
                and isinstance(item["value"], str), "String %d metadata changed" % sid)
        if item["value"] == hbc.strings[sid]:
            continue
        entry = hbc.string_entries[sid]
        require(sid not in hbc.protected_strings,
                "String %d is an identifier or switch label" % sid)
        try:
            encoded = item["value"].encode("utf-16le" if entry["utf16"] else "latin1",
                                           errors="surrogatepass" if entry["utf16"] else "strict")
        except UnicodeError as exc:
            raise HBC98Error("String %d cannot use its original encoding" % sid) from exc
        require(len(encoded) == entry["bytes"], "String %d: encoded length changed" % sid)
        start, end = entry["offset"], entry["offset"] + entry["bytes"]
        for other_start, other_end, other_sid in spans:
            if other_start >= end:
                break
            require(other_sid == sid or other_end <= start,
                    "String %d shares storage with string %d" % (sid, other_sid))
        output[start:end] = encoded


def load(path):
    path = Path(path)
    metadata = json.loads((path / HEADER).read_text(encoding="utf-8"))
    require(metadata.get("formatVersion") == FORMAT and metadata.get("profile") == OPCODE_PROFILE["profile"]
            and metadata.get("hermesCommit") == OPCODE_PROFILE["hermes_commit"]
            and metadata.get("opcodeSourceSha256") == OPCODE_PROFILE["source_sha256"],
            "Unsupported HASM profile")
    hbc = HBC98((path / ORIGINAL).read_bytes())
    require(metadata["inputSha256"] == hbc.raw_sha256() and metadata["header"] == hbc.header
            and {k: list(v) for k, v in hbc.sections.items()} == metadata["sections"]
            and metadata["functionCount"] == hbc.getFunctionCount()
            and metadata["stringCount"] == hbc.getStringCount(),
            "Original HBC and metadata disagree")
    output = bytearray(hbc.data)
    expected_switches = []
    with (path / INSTRUCTIONS).open(encoding="utf-8") as stream:
        for fid, fh in enumerate(hbc.functions):
            raw_header = stream.readline()
            require(raw_header.startswith("@function "), "Missing function %d HASM header" % fid)
            try:
                parsed_header = json.loads(raw_header[len("@function "):])
            except json.JSONDecodeError as exc:
                raise HBC98Error("Function %d: malformed HASM header" % fid) from exc
            require(parsed_header == fh, "Function %d: header metadata changed" % fid)
            instructions = hbc.validate_function(fid)
            starts = {entry[0] for entry in instructions}
            for original in instructions:
                switch = hbc.switch_table(fid, original)
                if switch is not None:
                    expected_switches.append(switch)
                line = stream.readline()
                require(line != "" and not line.startswith("@end"),
                        "Function %d: missing instruction at 0x%x" % (fid, original[0]))
                patch = _parse_instruction(line, fid, None, original, starts, hbc)
                if patch is not None:
                    at = fh["offset"] + original[0]
                    output[at:at + len(patch)] = patch
            require(stream.readline().strip() == "@end", "Function %d: extra or missing instructions" % fid)
        require(not stream.read().strip(), "Extra functions in HASM")
    _patch_strings(hbc, (path / STRINGS).read_text(encoding="utf-8"), output)
    expected_content = _json(expected_switches) + "\n"
    require((path / SWITCHES).read_text(encoding="utf-8") == expected_content
            and metadata.get("switchTablesSha256") == hashlib.sha256(expected_content.encode("utf-8")).hexdigest(),
            "Switch table sidecar differs from original HBC")
    if output != hbc.data:
        output[-20:] = hashlib.sha1(output[:-20]).digest()
    rebuilt = HBC98(bytes(output))
    for fid in range(rebuilt.getFunctionCount()):
        rebuilt.validate_function(fid)
    return rebuilt
