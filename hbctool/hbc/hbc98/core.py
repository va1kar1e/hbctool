"""Bounded HBC v98 reader and byte-preserving, same-layout assembler.

The wire format and opcode order come from the pinned Meta Hermes source in
reference/. No application bytecode is executed by this module.
"""

import hashlib
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
MAGIC = 0x1F1903C103BC1FC6
FIELDS = ("fileLength globalCodeIndex functionCount stringKindCount identifierCount "
          "stringCount overflowStringCount stringStorageSize bigIntCount bigIntStorageSize "
          "regExpCount regExpStorageSize literalValueBufferSize objKeyBufferSize "
          "objShapeTableCount numStringSwitchImms segmentID cjsModuleCount "
          "functionSourceCount debugInfoOffset").split()
TYPES = {"Reg8": "B", "Reg32": "I", "UInt8": "B", "UInt16": "H",
         "UInt32": "I", "Addr8": "b", "Addr32": "i", "Imm32": "i",
         "Double": "Q"}  # Double is represented as its exact 64-bit bit pattern.
OPCODE_PROFILE = json.loads((HERE / "opcode.json").read_text(encoding="utf-8"))
OPCODES = OPCODE_PROFILE["opcodes"]
BY_NAME = {entry["name"]: entry for entry in OPCODES}


class HBC98Error(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise HBC98Error(message)


def align4(offset):
    return (offset + 3) & ~3


def u32(data, offset):
    return struct.unpack_from("<I", data, offset)[0]


class HBC98:
    version = 98
    profile = OPCODE_PROFILE["profile"]

    def __init__(self, source):
        if hasattr(source, "input"):  # hbctool.util.BitReader
            source = source.input
        self.data = source.read() if hasattr(source, "read") else bytes(source)
        self._parse()

    def _take(self, name, position, length, limit=None, align_after=True):
        limit = len(self.data) - 20 if limit is None else limit
        require(0 <= position <= limit and 0 <= length <= limit - position,
                "%s outside file at 0x%x (%d bytes)" % (name, position, length))
        self.sections[name] = (position, length)
        return align4(position + length) if align_after else position + length

    def _parse(self):
        data = self.data
        require(len(data) >= 148, "Truncated HBC v98 header/footer")
        magic, version = struct.unpack_from("<QI", data)
        require(magic == MAGIC and version == 98, "Expected Hermes HBC v98")
        self.header = dict(zip(FIELDS, struct.unpack_from("<20I", data, 32)))
        self.header.update(magic=magic, version=version,
                           sourceHash=list(data[12:32]), options=data[112],
                           padding=data[113:128].hex())
        require(self.header["fileLength"] == len(data), "fileLength differs from input size")
        require(hashlib.sha1(data[:-20]).digest() == data[-20:], "Invalid HBC footer SHA-1")
        self.sections = {"header": (0, 128)}
        end = self.header["debugInfoOffset"]
        require(128 <= end <= len(data) - 20, "Invalid debugInfoOffset")
        cursor = self._take("functionHeaders", 128, 12 * self.header["functionCount"], end)
        cursor = self._take("stringKinds", cursor, 4 * self.header["stringKindCount"], end)
        cursor = self._take("identifierHashes", cursor, 4 * self.header["identifierCount"], end)
        cursor = self._take("stringTable", cursor, 4 * self.header["stringCount"], end)
        cursor = self._take("overflowStrings", cursor, 8 * self.header["overflowStringCount"], end)
        cursor = self._take("stringStorage", cursor, self.header["stringStorageSize"], end)
        cursor = self._take("literalValues", cursor, self.header["literalValueBufferSize"], end)
        cursor = self._take("objectKeys", cursor, self.header["objKeyBufferSize"], end)
        cursor = self._take("objectShapes", cursor, 8 * self.header["objShapeTableCount"], end)
        cursor = self._take("bigIntTable", cursor, 8 * self.header["bigIntCount"], end)
        cursor = self._take("bigIntStorage", cursor, self.header["bigIntStorageSize"], end)
        cursor = self._take("regExpTable", cursor, 8 * self.header["regExpCount"], end)
        cursor = self._take("regExpStorage", cursor, self.header["regExpStorageSize"], end)
        cursor = self._take("cjsModules", cursor, 8 * self.header["cjsModuleCount"], end)
        cursor = self._take("functionSources", cursor, 8 * self.header["functionSourceCount"], end)
        self.sections["bytecodeAndInfo"] = (cursor, end - cursor)
        require(cursor <= end, "Bytecode sections overlap debug information")
        self._parse_strings()
        self._parse_functions(cursor, end)
        self._parse_other_tables()
        self._parse_debug(end)

    def _parse_strings(self):
        data, h = self.data, self.header
        kind_pos = self.sections["stringKinds"][0]
        self.string_kinds = []
        self.identifier_ids = set()
        for i in range(h["stringKindCount"]):
            word = u32(data, kind_pos + i * 4)
            count, kind = word & 0x7fffffff, word >> 31
            first = len(self.string_kinds)
            self.string_kinds.extend([kind] * count)
            if kind:
                self.identifier_ids.update(range(first, first + count))
        require(len(self.string_kinds) == h["stringCount"], "String kind counts disagree")
        require(len(self.identifier_ids) == h["identifierCount"], "Identifier count disagrees")
        table = self.sections["stringTable"][0]
        overflow = self.sections["overflowStrings"][0]
        storage = self.sections["stringStorage"][0]
        self.string_entries = []
        self.strings = []
        self.protected_strings = set(self.identifier_ids)
        for sid in range(h["stringCount"]):
            word = u32(data, table + sid * 4)
            utf16 = bool(word & 1)
            offset = (word >> 1) & 0x7fffff
            length = word >> 24
            if length == 255:
                require(offset < h["overflowStringCount"], "String %d: overflow ID out of range" % sid)
                offset, length = struct.unpack_from("<II", data, overflow + offset * 8)
            size = length * (2 if utf16 else 1)
            require(offset <= h["stringStorageSize"] and size <= h["stringStorageSize"] - offset,
                    "String %d: storage span out of range" % sid)
            absolute = storage + offset
            raw = data[absolute:absolute + size]
            value = raw.decode("utf-16le" if utf16 else "latin1", errors="surrogatepass")
            self.string_entries.append({"offset": absolute, "length": length,
                                        "bytes": size, "utf16": utf16})
            self.strings.append(value)

    def _parse_functions(self, bytecode_start, bytecode_end):
        data = self.data
        table = self.sections["functionHeaders"][0]
        self.functions = []
        for fid in range(self.header["functionCount"]):
            word1, word2 = struct.unpack_from("<II", data, table + fid * 12)
            small = data[table + fid * 12 + 8:table + fid * 12 + 12]
            flag = small[3]
            if flag & 0x20:
                large_at = ((word2 >> 14) & 0xff) << 24 | (word1 & 0x1ffffff)
                require(bytecode_start <= large_at <= bytecode_end - 37,
                        "Function %d: overflow header outside function info at 0x%x" % (fid, large_at))
                fields = struct.unpack_from("<8I", data, large_at)
                offset, params, loop, size, name, numbers, nonptr, frame = fields
                read_cache, write_cache, new_object_cache, private_cache = data[large_at + 32:large_at + 36]
                flag = data[large_at + 36]
                info_at = large_at
            else:
                offset, params, loop = word1 & 0x1ffffff, (word1 >> 25) & 31, word1 >> 30
                size, name = word2 & 0x3fff, (word2 >> 14) & 0xff
                numbers, nonptr = (word2 >> 22) & 31, (word2 >> 27) & 31
                frame = small[0]
                read_cache = small[1]
                write_cache = small[2] & 0x3f
                new_object_cache = (small[2] >> 6) & 1
                private_cache = (small[2] >> 7) & 1
                info_at = None
            require(name < len(self.strings), "Function %d: functionName ID %d out of range" % (fid, name))
            require(numbers + nonptr <= frame,
                    "Function %d: register class counts exceed frame" % fid)
            require(bytecode_start <= offset <= bytecode_end and size <= bytecode_end - offset,
                    "Function %d: bytecode span 0x%x+%d outside file" % (fid, offset, size))
            self.functions.append({"id": fid, "offset": offset, "size": size,
                                   "name": name, "params": params, "loopDepth": loop,
                                   "frameSize": frame, "numberRegCount": numbers,
                                   "nonPtrRegCount": nonptr,
                                   "readCacheSize": read_cache,
                                   "writeCacheSize": write_cache,
                                   "numCacheNewObject": new_object_cache,
                                   "privateNameCacheSize": private_cache,
                                   "flags": flag,
                                   "overflowHeader": info_at})

    def _parse_other_tables(self):
        data, h = self.data, self.header
        for name, count, storage_name in (("bigIntTable", h["bigIntCount"], "bigIntStorage"),
                                          ("regExpTable", h["regExpCount"], "regExpStorage")):
            at = self.sections[name][0]
            capacity = self.sections[storage_name][1]
            for i in range(count):
                off, size = struct.unpack_from("<II", data, at + 8 * i)
                require(off <= capacity and size <= capacity - off,
                        "%s entry %d outside storage" % (name, i))
        shapes = self.sections["objectShapes"][0]
        self.shapes = []
        for i in range(h["objShapeTableCount"]):
            offset, count = struct.unpack_from("<II", data, shapes + i * 8)
            require(offset <= h["objKeyBufferSize"] and count <= h["objKeyBufferSize"],
                    "Object shape %d outside key buffer" % i)
            ids = self._literal_sequence("objectKeys", offset, count)
            self.protected_strings.update(ids)
            self.shapes.append((offset, count))
        self._checked_literals = set()
        for i in range(h["functionSourceCount"]):
            fid, sid = struct.unpack_from("<II", data, self.sections["functionSources"][0] + 8 * i)
            require(fid < h["functionCount"] and sid < h["stringCount"],
                    "Function source %d has invalid reference" % i)

    def _literal_sequence(self, section, offset, count):
        """Validate one run-encoded literal sequence and return string IDs."""
        start, capacity = self.sections[section]
        require(0 <= offset <= capacity and count <= capacity,
                "%s literal sequence outside buffer" % section)
        position = start + offset
        end = start + capacity
        seen = 0
        string_ids = set()
        payload_size = (0, 0, 0, 8, 4, 2, 0, 4)
        while seen < count:
            require(position < end, "%s literal sequence truncated at 0x%x" % (section, position))
            tag_byte = self.data[position]
            position += 1
            tag = (tag_byte >> 4) & 7
            group = tag_byte & 15
            if tag_byte & 128:
                require(position < end, "%s extended tag truncated" % section)
                group = (group << 8) | self.data[position]
                position += 1
            require(group > 0 and seen + group <= count,
                    "%s literal item count invalid at 0x%x" % (section, position - 1))
            width = payload_size[tag]
            require(group * width <= end - position,
                    "%s literal payload truncated at 0x%x" % (section, position))
            if tag in (4, 5):
                for i in range(group):
                    sid = int.from_bytes(self.data[position + i * width:position + (i + 1) * width], "little")
                    require(sid < self.header["stringCount"],
                            "%s string ID %d invalid at 0x%x" % (section, sid, position))
                    string_ids.add(sid)
            position += group * width
            seen += group
        return string_ids

    def _parse_debug(self, at):
        data = self.data
        require(at + 16 <= len(data) - 20, "Truncated debug info header")
        filenames, name_bytes, regions, debug_bytes = struct.unpack_from("<4I", data, at)
        pos = at + 16
        for name, size in (("debugFilenameTable", filenames * 8),
                           ("debugFilenameStorage", name_bytes),
                           ("debugRegions", regions * 12), ("debugData", debug_bytes)):
            pos = self._take(name, pos, size, align_after=False)
        require(pos <= len(data) - 20, "Debug info overlaps footer")
        self.sections["footer"] = (len(data) - 20, 20)

    def getHeader(self):
        return self.header

    def getVersion(self):
        return self.version

    def getFunctionCount(self):
        return len(self.functions)

    def getStringCount(self):
        return len(self.strings)

    def getString(self, sid):
        require(0 <= sid < len(self.strings), "String ID out of range")
        return self.strings[sid], self.string_entries[sid]

    def getFunction(self, fid, disasm=True):
        require(0 <= fid < len(self.functions), "Function ID out of range")
        fh = self.functions[fid]
        code = self.data[fh["offset"]:fh["offset"] + fh["size"]]
        return (self.strings[fh["name"]], fh["params"], fh["frameSize"],
                None, self.instructions(fid) if disasm else code, fh)

    def instructions(self, fid):
        fh = self.functions[fid]
        code = self.data[fh["offset"]:fh["offset"] + fh["size"]]
        pos, result = 0, []
        while pos < len(code):
            start = pos
            opcode = code[pos]
            require(opcode < len(OPCODES), "Function %d offset 0x%x: unknown opcode %d" % (fid, pos, opcode))
            definition = OPCODES[opcode]
            pos += 1
            values = []
            for index, typ in enumerate(definition["operands"]):
                fmt = TYPES[typ]
                size = struct.calcsize(fmt)
                require(pos + size <= len(code), "Function %d offset 0x%x: truncated %s" % (fid, start, typ))
                value = struct.unpack_from("<" + fmt, code, pos)[0]
                values.append(value)
                pos += size
            result.append((start, definition, values, pos))
        return result

    def validate_function(self, fid):
        fh = self.functions[fid]
        instructions = self.instructions(fid)
        starts = {entry[0] for entry in instructions}
        for pos, definition, values, end in instructions:
            name = definition["name"]
            for index, (typ, value) in enumerate(zip(definition["operands"], values)):
                meaning = definition["meanings"].get(str(index))
                count_name = {"string": "stringCount", "function": "functionCount",
                              "bigint": "bigIntCount"}.get(meaning)
                if count_name:
                    require(value < self.header[count_name],
                            "Function %d offset 0x%x: %s ID %d out of range" % (fid, pos, meaning, value))
                if typ in ("Reg8", "Reg32"):
                    require(value < fh["frameSize"],
                            "Function %d offset 0x%x: register %d outside frame" % (fid, pos, value))
                if typ in ("Addr8", "Addr32"):
                    require(pos + value in starts,
                            "Function %d offset 0x%x: branch target 0x%x invalid" % (fid, pos, pos + value))
            if name == "UIntSwitchImm":
                table = align4(fh["offset"] + pos + values[1])
                lo, hi = values[3:5]
                require(hi >= lo and hi - lo < 1000000, "Function %d: invalid integer switch range" % fid)
                require(fh["offset"] + fh["size"] <= table
                        and table + 4 * (hi - lo + 1) <= self.header["debugInfoOffset"],
                        "Function %d: integer switch table outside file" % fid)
                for i in range(hi - lo + 1):
                    relative = struct.unpack_from("<i", self.data, table + i * 4)[0]
                    require(pos + relative in starts,
                            "Function %d: integer switch target invalid" % fid)
            elif name == "StringSwitchImm":
                table = align4(fh["offset"] + pos + values[2])
                count = values[4]
                require(values[1] < self.header["numStringSwitchImms"]
                        and count <= self.header["stringCount"]
                        and fh["offset"] + fh["size"] <= table
                        and table + count * 8 <= self.header["debugInfoOffset"],
                        "Function %d: string switch table outside file" % fid)
                for i in range(count):
                    sid, relative = struct.unpack_from("<Ii", self.data, table + i * 8)
                    require(sid < self.header["stringCount"] and pos + relative in starts,
                            "Function %d: string switch case invalid" % fid)
                    self.protected_strings.add(sid)
            elif name in ("NewArrayWithBuffer", "NewArrayWithBufferLong"):
                literal_offset, literal_count = values[3], values[2]
                key = (literal_offset, literal_count)
                if key not in self._checked_literals:
                    self._literal_sequence("literalValues", literal_offset, literal_count)
                    self._checked_literals.add(key)
            elif name in ("NewObjectWithBuffer", "NewObjectWithBufferLong",
                          "NewObjectWithBufferAndParent"):
                shape_index = values[2] if name == "NewObjectWithBufferAndParent" else values[1]
                literal_offset = values[3] if name == "NewObjectWithBufferAndParent" else values[2]
                require(shape_index < len(self.shapes),
                        "Function %d offset 0x%x: object shape ID invalid" % (fid, pos))
                key = (literal_offset, self.shapes[shape_index][1])
                if key not in self._checked_literals:
                    self._literal_sequence("literalValues", *key)
                    self._checked_literals.add(key)
        return instructions

    def switch_table(self, fid, instruction):
        """Return decoded switch cases with function-relative branch targets."""
        pos, definition, values, _ = instruction
        name = definition["name"]
        fh = self.functions[fid]
        if name == "UIntSwitchImm":
            table = align4(fh["offset"] + pos + values[1])
            cases = [{"value": values[3] + i,
                      "target": pos + struct.unpack_from("<i", self.data, table + 4 * i)[0]}
                     for i in range(values[4] - values[3] + 1)]
            return {"function": fid, "instructionOffset": pos, "kind": "integer",
                    "tableOffset": table, "defaultTarget": pos + values[2], "cases": cases}
        if name == "StringSwitchImm":
            table = align4(fh["offset"] + pos + values[2])
            cases = []
            for i in range(values[4]):
                sid, relative = struct.unpack_from("<Ii", self.data, table + 8 * i)
                cases.append({"stringId": sid, "target": pos + relative})
            return {"function": fid, "instructionOffset": pos, "kind": "string",
                    "globalSwitchId": values[1], "tableOffset": table,
                    "defaultTarget": pos + values[3], "cases": cases}
        return None

    def export(self, writer):
        writer.writeall(self.data)

    def raw_sha256(self):
        return hashlib.sha256(self.data).hexdigest()
