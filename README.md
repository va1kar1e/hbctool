# hbctool 

[![Python 3.x](https://img.shields.io/badge/python-3.x-yellow.svg)](https://python.org) [![PyPI version](https://badge.fury.io/py/hbctool.svg)](https://badge.fury.io/py/hbctool) [![Software License](https://img.shields.io/badge/license-MIT-brightgreen.svg)](/LICENSE)

A command-line interface for disassembling and assembling the Hermes Bytecode.

## New in this branch: HBC v98 support

This branch adds a Hermes Bytecode **v98 disassembler and constrained assembler**
while keeping the existing command-line interface and older backends.

- **Pinned version profile:** the file layout and 219 opcodes come from Meta's
  `hermes-v250829098.0.10` definitions, including operand types and
  string/function/BigInt references. The source definitions and generator are
  included so the opcode table can be reproduced.
- **v98 parsing:** function and string overflow entries, literal buffers,
  object shapes, BigInt, RegExp, module/source tables, exception/debug metadata,
  and integer/string switch tables. Strings retain their 8-bit or UTF-16LE
  encoding, BOM, and surrogate code units.
- **HASM format 2:** readable instructions, actual function-header fields,
  decoded switch cases, metadata, and an original-bytecode snapshot preserve
  padding and sections that are not edited. Floating-point operands use exact
  64-bit representations to preserve NaN payloads and negative zero.
- **Controlled edits:** change operands or replace instructions with compatible
  operand layouts; change eligible literal strings without changing encoding
  or encoded length. Assembly validates references, registers, branch targets,
  headers, and side tables, and refreshes the footer checksum after edits.
- **Backward compatibility:** legacy HBC backends and HASM loading remain
  available. Unknown bytecode versions are rejected.

The assembler preserves the original layout. Growing/shrinking instructions or
strings, adding functions or strings, moving sections, and changing switch
tables are unsupported. Identifier strings, shape keys, switch labels, and
strings that overlap another storage entry cannot be edited. This release does
not add JavaScript decompilation or a v99 profile.

Install this branch from its checkout (the PyPI command below refers to the
upstream package):

```sh
python -m venv .venv
# Activate .venv using your shell, then:
python -m pip install .
hbctool disasm input.bundle output_hasm
hbctool asm output_hasm rebuilt.bundle
```

Only tool source and documentation are included in the v98 update. Keep input
bundles, extracted strings, generated HASM, device captures, test fixtures,
credentials, and reports outside version control. The ignore rules help prevent
accidental additions; inspect staged changes before committing.

---

Since the React Native team created their own JavaScript engine (named Hermes) for running the React Native application, the JavaScript source code is often compiled to the Hermes bytecode. In the penetration test project, I found that some React Native applications have already been migrated to the Hermes engine. It is really head for me to analyze or patch those applications. Therefore, I created hbctool for helping any pentester to test the Hermes bytecode.

> [Hermes](https://hermesengine.dev/) is an open-source JavaScript engine optimized for running React Native apps on Android. For many apps, enabling Hermes will result in improved start-up time, decreased memory usage, and smaller app size. At this time Hermes is an opt-in React Native feature, and this guide explains how to enable it.

Special thanks to [ErbaZZ](https://github.com/ErbaZZ) and [Jusmistic](https://github.com/Jusmistic) for helping me research and develop this tool.

For more information, please visit:

[https://suam.wtf/posts/react-native-application-static-analysis-en/](https://suam.wtf/posts/react-native-application-static-analysis-en/)

## Screenshot

![hbctool Example](/image/hbctool_example.gif)

This video with MP4 format can be found at [/image/hbctool_example.mp4](/image/hbctool_example.mp4).

## Installation

To install hbctool, simply use pip:

```
pip install hbctool
```

## Usage

Please run `hbctool --help` to show the usage.

```
hbctool --help   
A command-line interface for disassembling and assembling
the Hermes Bytecode.

Usage:
    hbctool disasm <HBC_FILE> <HASM_PATH>
    hbctool asm <HASM_PATH> <HBC_FILE>
    hbctool --help
    hbctool --version

Operation:
    disasm              Disassemble Hermes Bytecode
    asm                 Assemble Hermes Bytecode

Args:
    HBC_FILE            Target HBC file
    HASM_PATH           Target HASM directory path

Options:
    --version           Show hbctool version
    --help              Show hbctool help manual

Examples:
    hbctool disasm index.android.bundle test_hasm
    hbctool asm test_hasm index.android.bundle
```

> For Android, the HBC file normally locates at `assets` directory with `index.android.bundle` filename.

## Support

hbctool currently supports the following Hermes Bytecode version:

- [Hermes Bytecode version 59](/hbctool/hbc/hbc59/)
- [Hermes Bytecode version 62](/hbctool/hbc/hbc62/)
- [Hermes Bytecode version 74](/hbctool/hbc/hbc74/)
- [Hermes Bytecode version 76](/hbctool/hbc/hbc76/)
- Hermes Bytecode versions 84 and 85 (existing backends on this branch)
- Hermes Bytecode version 98 (profile `hermes-v250829098.0.10`)

### HBC v98 workflow

The v98 parser uses the pinned Hermes source at commit
`becc964bd16002569bf74c4d8c190cfd2ad38985`. Run the usual commands:

```text
hbctool disasm index.android.bundle bundle_hasm
hbctool asm bundle_hasm rebuilt.bundle
```

The v98 HASM directory contains `instruction.hasm`, `string.json`,
`switch_tables.json`, `metadata.json`, and an immutable `original.hbc` snapshot.
The instruction file exposes actual v98 function header fields and encodes
`Double` operands as exact 64-bit hex values. Switch case targets are decoded
in `switch_tables.json`. Only `instruction.hasm` and supported entries in
`string.json` are editable. Assembly checks the snapshot, header, table layout,
references, instruction positions, and string storage. It accepts same-size
instruction changes and same-encoding, same-length literal string changes;
unsupported structural edits fail with an error. The SHA-1 footer is refreshed
for changed files. An unchanged disassembly reassembles byte for byte.

Use `python -m hbctool.hbc.hbc98.generate_profile` to rebuild the opcode table
from the pinned `reference/BytecodeList.def`. Review the diff before supporting
another bytecode version; changing the version number alone is insufficient.
Compiler fixtures, device outputs, and private validation materials are not
distributed with this branch. Use a separate local workspace for validation.

## Contribution

Feel free to create an issue or submit the merge request. Anyway you want to contribute this project. I'm very happy about it.

However, please run the unit test before submiting the pull request.

```
cd hbctool
python test.py
```

I use poetry to build this tool. To build it yourself, simply execute:

1. `poetry install`
2. `poetry build`
4. `pip install --force-reinstall dist/hbctool-<VERSION>-py3-none-any.whl`

## Next Step

- Add the other Hermes bytecode versions
- Create a class abstraction
- Support overflow patching
- Do all TODO, NOTE, FIXME in source code
