# Totoro - Semantic ROP Chain Synthesizer

<div align="center">

![Totoro](https://img.shields.io/badge/Totoro-Synthesizer-ff6b6b?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.8+-4c1d95?style=for-the-badge)
![Z3](https://img.shields.io/badge/Z3-Constraint%20Solver-0066cc?style=for-the-badge)
![Capstone](https://img.shields.io/badge/Capstone-Disassembly-2d3748?style=for-the-badge)

**Semantic ROP chain synthesis with z3-powered constraint solving**

</div>

---

## Overview

**Totoro** is a semantic ROP (Return-Oriented Programming) chain synthesizer that uses SMT solving to find optimal gadget sequences for exploit development. Named after the friendly forest spirit, it helps you navigate the wilderness of binary exploitation.

## Features

- **Semantic Analysis**: Lifts x86-64 instructions using Capstone
- **Z3 Integration**: Uses Microsoft's Z3 theorem prover for constraint solving
- **Flexible Constraints**: Express complex register constraints with arithmetic operations
- **Fast Search**: Efficient gadget discovery and chain synthesis

## Installation

```bash
pip install -e .
```

### Dependencies

- Python 3.8+
- Capstone (disassembly engine)
- Z3 Solver (SMT constraint solving)

### Optional Dependencies

```bash
pip install -e ".[pwntools]"  # For enhanced binary analysis
pip install -e ".[dev]"      # For development
```

## Usage

### Basic Usage

```bash
# Simple register assignment
python -m totoro /bin/ls "rax = rbx"

# With arithmetic
python -m totoro /bin/ls "rax = rax + 0x100"

# Memory read with offset
python -m totoro /bin/ls "rax = read(rdi + 0x20)"

# Complex constraint
python -m totoro /bin/ls "rax = read(rdi + 0x20) + 0x100"
```

### Search for Gadgets

```bash
# Find gadgets matching a pattern
python -m totoro /bin/ls --search "pop rax"

# Short form
python -m totoro /bin/ls -s "xchg rax"
```

### Statistics

```bash
# View gadget statistics for a binary
python -m totoro /bin/ls --stats
```

## Constraint Language

Totoro supports the following constraint expressions:

| Operation | Syntax | Description |
|-----------|--------|-------------|
| Assignment | `rax = rbx` | Set register |
| Addition | `rax = rax + 0x10` | Add immediate to register |
| Memory Read | `rax = read(rdi)` | Read from memory address |
| Memory + Offset | `rax = read(rdi + 0x20)` | Read with offset |
| Complex | `rax = read(rdi + 0x20) + 0x100` | Combined operations |

## Architecture

```
totoro/
├── __init__.py      # Package initialization
├── gadget.py        # Gadget representation and Capstone lifting
├── engine.py        # Z3 constraint solver engine
├── synthesizer.py   # Main synthesis logic
└── cli.py           # Command-line interface
```

### Core Components

**gadget.py**
- `Gadget`: Represents a single ROP gadget with semantic information
- `GadgetSet`: Collection of gadgets extracted from a binary

**engine.py**
- `ConstraintEngine`: Z3-based constraint solving and gadget effect modeling

**synthesizer.py**
- `Synthesizer`: Main interface for chain synthesis
- `SynthesizedChain`: Result of successful synthesis

## Examples

### Finding a Simple Gadget Chain

```python
from totoro import Synthesizer

synth = Synthesizer()
synth.load_binary("/bin/ls")

chain = synth.synthesize("rax = rbx")
if chain:
    print(chain)
```

### Searching for Specific Gadgets

```python
from totoro import Synthesizer

synth = Synthesizer()
synth.load_binary("/bin/ls")

# Find all pop gadgets
pop_gadgets = synth.find_gadget("pop")
for g in pop_gadgets[:10]:
    print(f"0x{g.address:x}: {g.instruction}")
```

## API Reference

### Synthesizer

```python
synth = Synthesizer()
count = synth.load_binary(path)        # Load gadgets from binary
chain = synth.synthesize(constraint)   # Synthesize ROP chain
results = synth.find_gadget(pattern)   # Search gadgets
stats = synth.get_statistics()          # Get gadget stats
```

### Gadget

```python
g.address      # Gadget address
g.instruction  # Disassembled instruction
g.regs_read    # Registers read by gadget
g.regs_write   # Registers written by gadget
g.semantic     # Extracted semantic information
```

## License

MIT License - See LICENSE file for details.

---

<div align="center">

**Totoro** - Your companion in the forest of binary exploitation

</div>
