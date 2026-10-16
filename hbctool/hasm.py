from .util import *
import hbctool.hbc as hbcl
import json
import os
import shutil
import re

def write_func(f, func, i, hbc):
    functionName, paramCount, registerCount, symbolCount, insts, _ = func
    f.write(f"Function<{functionName}>{i}({paramCount} params, {registerCount} registers, {symbolCount} symbols):\n")
    for opcode, operands in insts:
        f.write(f"\t{opcode.ljust(20,' ')}\t")
        o = []
        ss = []
        for ii, v in enumerate(operands):
            t, is_str, val = v
            o.append(f"{t}:{val}")

            if is_str:
                s, _ = hbc.getString(val)
                ss.append((ii, val, s))
                
        
        f.write(f"{', '.join(o)}\n")
        if len(ss) > 0:
            for ii, val, s in ss:
                f.write(f"\t; Oper[{ii}]: String({val}) {repr(s)}\n")

            f.write("\n")

    f.write("EndFunction\n\n")

def dump(hbc, path, force=False):
    from hbctool.hbc.hbc98 import HBC98
    if isinstance(hbc, HBC98):
        from hbctool.hbc.hbc98.hasm import dump as dump98
        return dump98(hbc, path)
    
    if os.path.exists(path) and not force:
        c = input(f"'{path}' exists. Do you want to remove it ? (y/n): ").lower().strip()
        if c[:1] == "y":
            shutil.rmtree(path)
        else:
            exit(1337)
    
    shutil.rmtree(path, ignore_errors=True)
    os.makedirs(path)
    # Write all obj to metadata.json
    f = open(f"{path}/metadata.json", "w")
    json.dump(hbc.getObj(), f)
    f.close()
    
    stringCount = hbc.getStringCount()
    functionCount = hbc.getFunctionCount()

    ss = []
    for i in range(stringCount):
        val, header = hbc.getString(i)
        ss.append({
            "id": i,
            "isUTF16": header[0] == 1,
            "value": val
        })
    
    f = open(f"{path}/string.json", "w")
    json.dump(ss, f, indent=4)
    f.close()

    f = open(f"{path}/instruction.hasm", "w")
    for i in range(functionCount):
        write_func(f, hbc.getFunction(i), i, hbc)
    f.close()

def read_all_func(hasm, hbc):
    func_asms = [func_asm + "EndFunction" for func_asm in hasm.split("EndFunction\n\n")[:-1]]
    functionCount = hbc.getFunctionCount()

    rs = [''] * functionCount

    for func_asm in func_asms:
        m = re.search(r"Function<.*?>([0-9]+)\([0-9]+ params, [0-9]+ registers,\s?[0-9]+ symbols\):", func_asm)
        assert m, f"Malicious function header: {func_asm}"

        fid = int(m.group(1))

        assert fid >= 0 and fid < functionCount, f"Malicious function ID: {fid} (must lower than {functionCount})"

        rs[fid] = func_asm
    
    return rs


def read_func(func_asms, i):
    func_asm = func_asms[i]

    m = re.search(r"Function<.*?>([0-9]+)\(([0-9]+) params, ([0-9]+) registers,\s?([0-9]+) symbols\):\n(.+?)\nEndFunction", func_asm, re.DOTALL)
    assert m, f"Malicious function header: {func_asm}"

    functionName = m.group(1)
    paramCount = int(m.group(2))
    registerCount = int(m.group(3))
    symbolCount = int(m.group(4))
    insts_asm = m.group(5)

    inst_lines = insts_asm.split("\n")

    insts = []

    for inst_line in inst_lines:
        inst_line = inst_line.strip()

        if len(inst_line) == 0 or inst_line.startswith(";"):
            continue

        inst_words = inst_line.split()

        opcode = inst_words[0]

        operands = []
        for oper in inst_words[1:]:
            oper_t, val = oper.replace(",", "").split(":")
            
            if oper_t == 'Double':
                val = float(val)
            else:
                val = int(val)
            
            operands.append((oper_t, False, val))
        
        insts.append((opcode, operands))
    
    return functionName, paramCount, registerCount, symbolCount, insts, None


def load(path):
    metadata_path = os.path.join(path, "metadata.json")
    if os.path.isfile(metadata_path):
        with open(metadata_path, encoding="utf-8") as meta_file:
            version_metadata = json.load(meta_file)
        if version_metadata.get("formatVersion") == 2:
            from hbctool.hbc.hbc98.hasm import load as load98
            return load98(path)
        if version_metadata.get("version") == 98 or version_metadata.get("header", {}).get("version") == 98:
            raise ValueError("HBC v98 requires HASM format 2")
    assert os.path.exists(path), f"{path} does not exists."
    assert os.path.exists(f"{path}/metadata.json"), f"metadata.json not found."
    assert os.path.exists(f"{path}/string.json"), f"string.json not found."
    assert os.path.exists(f"{path}/instruction.hasm"), f"instruction.hasm not found."

    f = open(f"{path}/metadata.json", "r")
    hbc = hbcl.loado(json.load(f))
    f.close()

    f = open(f"{path}/instruction.hasm", "r")
    hasm_content = f.read()
    f.close()

    f = open(f"{path}/string.json", "r")
    strings = json.load(f)
    f.close()

    for string in strings:
        hbc.setString(string["id"], string["value"])
  
    func_asms = read_all_func(hasm_content, hbc)
    for i in range(len(func_asms)):
        func = read_func(func_asms, i)
        hbc.setFunction(i, func)

        
    return hbc

