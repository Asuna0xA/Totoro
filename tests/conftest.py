import pytest
import struct
import tempfile
import os
from pathlib import Path


@pytest.fixture
def sample_x86_bytes():
    return bytes([
        0x48, 0x89, 0xC7,  # mov rdi, rax
        0xC3              # ret
    ])


@pytest.fixture
def sample_gadget_bytes():
    return {
        'mov_reg': bytes([
            0x48, 0x89, 0xD8,  # mov rax, rbx
            0xC3              # ret
        ]),
        'add_imm': bytes([
            0x48, 0x83, 0xC0, 0x10,  # add rax, 0x10
            0xC3                      # ret
        ]),
        'lea_mem': bytes([
            0x48, 0x8D, 0x47, 0x20,  # lea rax, [rdi + 0x20]
            0xC3                      # ret
        ]),
        'pop_reg': bytes([
            0x58,  # pop rax
            0xC3   # ret
        ]),
        'xchg_reg': bytes([
            0x48, 0x87, 0xC3,  # xchg rbx, rax
            0xC3                 # ret
        ]),
        'sub_imm': bytes([
            0x48, 0x83, 0xE8, 0x08,  # sub rax, 8
            0xC3                      # ret
        ]),
    }


@pytest.fixture
def temp_binary(sample_gadget_bytes):
    with tempfile.NamedTemporaryFile(mode='wb', suffix='.bin', delete=False) as f:
        f.write(sample_gadget_bytes['mov_reg'])
        temp_path = f.name
    yield temp_path
    if os.path.exists(temp_path):
        os.unlink(temp_path)


@pytest.fixture
def constraint_expressions():
    return {
        'simple_reg': 'rax = rbx',
        'simple_imm_hex': 'rax = 0x100',
        'simple_imm_dec': 'rax = 256',
        'add_reg_imm': 'rax = rax + 0x10',
        'add_reg_imm_dec': 'rax = rax + 16',
        'sub_reg_imm': 'rax = rax - 8',
        'memory_read': 'rax = read(rdi)',
        'memory_read_offset': 'rax = read(rdi + 0x20)',
        'memory_write': 'rax = write(rsi)',
        'complex': 'rax = read(rdi + 0x20) + 0x100',
        'xor_op': 'rax = xor(rbx)',
        'lea_op': 'rax = lea(rbp - 8)',
    }


@pytest.fixture
def parser():
    from totoro.parser import ConstraintParser
    return ConstraintParser()


@pytest.fixture
def lifter():
    from totoro.gadget import GadgetLifter
    return GadgetLifter(base_address=0x400000)


@pytest.fixture
def gadget_set():
    from totoro.gadget import GadgetSet
    return GadgetSet(base_address=0x400000)


@pytest.fixture
def engine():
    from totoro.engine import ConstraintEngine
    return ConstraintEngine()


@pytest.fixture
def synthesizer():
    from totoro.synthesizer import Synthesizer
    return Synthesizer()
