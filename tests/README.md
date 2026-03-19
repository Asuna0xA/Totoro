# Tests

This directory contains pytest tests for the Totoro ROP chain synthesizer.

## Structure

- `__init__.py` - Package marker
- `conftest.py` - Shared pytest fixtures
- `test_parser.py` - Tests for constraint expression parsing
- `test_gadget.py` - Tests for gadget lifting and GadgetSet
- `test_synthesizer.py` - Tests for the main synthesis API

## Running Tests

Run all tests:
```bash
pytest tests/
```

Run specific test file:
```bash
pytest tests/test_parser.py
```

Run with verbose output:
```bash
pytest tests/ -v
```

Run with coverage:
```bash
pytest tests/ --cov=totoro
```

## Test Descriptions

### test_parser.py
Tests the constraint expression parser (`totoro.parser`):
- Simple register assignments: `rax = rbx`
- Immediate values: `rax = 0x100`, `rax = 256`
- Addition/subtraction: `rax = rax + 0x10`, `rax = rax - 8`
- Memory operations: `rax = read(rdi)`, `rax = write(rsi)`
- Complex expressions: `rax = read(rdi + 0x20) + 0x100`
- Error handling for invalid inputs
- Tokenization

### test_gadget.py
Tests the gadget lifter and GadgetSet classes (`totoro.gadget`):
- Lifting x86-64 instructions to Gadget objects
- Register read/write analysis
- Stack delta calculation
- Semantic effect extraction
- GadgetSet loading from binary files
- Gadget filtering by pattern, register, and effect type
- Statistics generation

### test_synthesizer.py
Tests the main synthesis API (`totoro.synthesizer`):
- Binary loading
- Constraint synthesis
- Gadget searching
- Statistics retrieval
- Integration tests for the full workflow

## Fixtures

The `conftest.py` file provides shared fixtures:
- `sample_gadget_bytes` - Pre-defined x86-64 bytecode sequences
- `temp_binary` - Temporary binary file for testing
- `constraint_expressions` - Sample constraint expressions
- `parser`, `lifter`, `gadget_set`, `engine`, `synthesizer` - Module instances
