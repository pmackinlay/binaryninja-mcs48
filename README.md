# Intel MCS-48 Architecture Plugin (v0.1)
Author: **Patrick Mackinlay**

_A disassembler, lifter and basic loader for the Intel MCS-48 architecture._

## Description

[This plugin](mcs48.py) disassembles Intel MCS-48 assembly code and generates LLIL.

The MCS-48 architecture plugin has the following known issues:

* calling conventions and platform are not working properly
* register and memory bank switching uses bad workarounds
* some instructions not implemented (movx, port I/O)

The binary view has the following known issues:

* no distinct signature for MCS-48 binaries
* no handling for external memory

## Installation

To install this plugin, navigate to your Binary Ninja plugins directory, and run:

```git clone https://github.com/pmackinlay/binaryninja-mcs48.git mcs48```

## Minimum Version

This plugin requires the following minimum version of Binary Ninja:

 * 1.1.1221

## License

This plugin is released under a [MIT](LICENSE) license.
