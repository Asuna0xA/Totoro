import pytest
from totoro.gadget import (
    GadgetLifter,
    GadgetSet,
    Gadget,
    OperandKind,
    Operand,
    SemanticEffect,
)


class TestGadgetLifter:
    def test_lift_mov_register(self, lifter):
        code = bytes([
            0x48, 0x89, 0xD8,  # mov rax, rbx
            0xC3              # ret
        ])
        gadget = lifter.lift(0x400000, code)
        assert gadget is not None
        assert gadget.address == 0x400000
        assert len(gadget.instructions) == 2
        assert 'mov' in gadget.instructions[0]
        assert 'ret' in gadget.instructions[1]
        assert gadget.num_instructions == 2
        assert gadget.size == len(code)

    def test_lift_add_immediate(self, lifter):
        code = bytes([
            0x48, 0x83, 0xC0, 0x10,  # add rax, 0x10
            0xC3                      # ret
        ])
        gadget = lifter.lift(0x400010, code)
        assert gadget is not None
        assert 'add' in gadget.instructions[0]
        assert 'rax' in gadget.instructions[0]

    def test_lift_lea_memory(self, lifter):
        code = bytes([
            0x48, 0x8D, 0x47, 0x20,  # lea rax, [rdi + 0x20]
            0xC3                      # ret
        ])
        gadget = lifter.lift(0x400020, code)
        assert gadget is not None
        assert 'lea' in gadget.instructions[0]

    def test_lift_pop_register(self, lifter):
        code = bytes([
            0x58,  # pop rax
            0xC3   # ret
        ])
        gadget = lifter.lift(0x400030, code)
        assert gadget is not None
        assert 'pop' in gadget.instructions[0]

    def test_lift_xchg(self, lifter):
        code = bytes([
            0x48, 0x87, 0xC3,  # xchg rbx, rax
            0xC3                 # ret
        ])
        gadget = lifter.lift(0x400040, code)
        assert gadget is not None
        assert 'xchg' in gadget.instructions[0]

    def test_lift_without_ret_returns_none(self, lifter):
        code = bytes([
            0x48, 0x89, 0xD8,  # mov rax, rbx
            0x90               # nop
        ])
        gadget = lifter.lift(0x400050, code)
        assert gadget is None

    def test_lift_invalid_code_returns_none(self, lifter):
        gadget = lifter.lift(0x400060, bytes([0xFF, 0xFF]))
        assert gadget is None

    def test_register_analysis_mov(self, lifter):
        code = bytes([
            0x48, 0x89, 0xC7,  # mov rdi, rax
            0xC3              # ret
        ])
        gadget = lifter.lift(0x400070, code)
        assert gadget is not None
        assert 'rax' in gadget.regs_read
        assert 'rdi' in gadget.regs_write

    def test_register_analysis_add(self, lifter):
        code = bytes([
            0x48, 0x01, 0xC7,  # add rdi, rax
            0xC3              # ret
        ])
        gadget = lifter.lift(0x400080, code)
        assert gadget is not None
        assert 'rax' in gadget.regs_read
        assert 'rdi' in gadget.regs_read
        assert 'rdi' in gadget.regs_write

    def test_stack_delta_push(self, lifter):
        code = bytes([
            0x50,  # push rax
            0xC3   # ret
        ])
        gadget = lifter.lift(0x400090, code)
        assert gadget is not None
        assert gadget.stack_delta == -8

    def test_stack_delta_pop(self, lifter):
        code = bytes([
            0x58,  # pop rax
            0xC3   # ret
        ])
        gadget = lifter.lift(0x4000A0, code)
        assert gadget is not None
        assert gadget.stack_delta == 8

    def test_stack_delta_sub_rsp(self, lifter):
        code = bytes([
            0x48, 0x83, 0xEC, 0x08,  # sub rsp, 8
            0xC3                      # ret
        ])
        gadget = lifter.lift(0x4000B0, code)
        assert gadget is not None
        assert gadget.stack_delta == -8

    def test_semantic_extraction_mov(self, lifter):
        code = bytes([
            0x48, 0x89, 0xD8,  # mov rax, rbx
            0xC3              # ret
        ])
        gadget = lifter.lift(0x4000C0, code)
        assert gadget is not None
        assert 'mov' in gadget.semantic
        assert gadget.semantic['mov'][0] == 'rax'
        assert gadget.semantic['mov'][1] == 'rbx'

    def test_semantic_extraction_add(self, lifter):
        code = bytes([
            0x48, 0x83, 0xC0, 0x10,  # add rax, 0x10
            0xC3                      # ret
        ])
        gadget = lifter.lift(0x4000D0, code)
        assert gadget is not None
        assert 'add' in gadget.semantic

    def test_semantic_extraction_lea(self, lifter):
        code = bytes([
            0x48, 0x8D, 0x47, 0x20,  # lea rax, [rdi + 0x20]
            0xC3                      # ret
        ])
        gadget = lifter.lift(0x4000E0, code)
        assert gadget is not None
        assert 'lea' in gadget.semantic

    def test_semantic_extraction_pop(self, lifter):
        code = bytes([
            0x58,  # pop rax
            0xC3   # ret
        ])
        gadget = lifter.lift(0x4000F0, code)
        assert gadget is not None
        assert 'pop' in gadget.semantic
        assert gadget.semantic['pop'] == 'rax'


class TestGadget:
    def test_gadget_creation(self):
        gadget = Gadget(
            address=0x400000,
            raw_bytes=bytes([0xC3]),
            instructions=['ret']
        )
        assert gadget.address == 0x400000
        assert gadget.num_instructions == 1
        assert gadget.size == 1

    def test_gadget_instruction_property(self):
        gadget = Gadget(
            address=0x400000,
            raw_bytes=bytes([0x90, 0xC3]),
            instructions=['nop', 'ret']
        )
        assert gadget.instruction == 'nop; ret'

    def test_reads_register(self):
        gadget = Gadget(
            address=0x400000,
            raw_bytes=bytes([0xC3]),
            instructions=['ret'],
            regs_read={'rax', 'rbx'}
        )
        assert gadget.reads_register('rax')
        assert gadget.reads_register('rbx')
        assert not gadget.reads_register('rdi')

    def test_writes_register(self):
        gadget = Gadget(
            address=0x400000,
            raw_bytes=bytes([0xC3]),
            instructions=['ret'],
            regs_write={'rdi', 'rsi'}
        )
        assert gadget.writes_register('rdi')
        assert gadget.writes_register('rsi')
        assert not gadget.writes_register('rax')

    def test_gadget_equality(self):
        g1 = Gadget(address=0x400000, raw_bytes=bytes([0xC3]))
        g2 = Gadget(address=0x400000, raw_bytes=bytes([0x90]))
        g3 = Gadget(address=0x400001, raw_bytes=bytes([0xC3]))
        assert g1 == g2
        assert g1 != g3

    def test_gadget_hash(self):
        g1 = Gadget(address=0x400000, raw_bytes=bytes([0xC3]))
        g2 = Gadget(address=0x400000, raw_bytes=bytes([0x90]))
        assert hash(g1) == hash(g2)


class TestGadgetSet:
    def test_gadgetset_creation(self, gadget_set):
        assert gadget_set.base_address == 0x400000
        assert gadget_set.max_gadgets == 50000
        assert len(gadget_set) == 0

    def test_load_from_binary(self, gadget_set, temp_binary):
        count = gadget_set.load_from_binary(temp_binary)
        assert count > 0
        assert len(gadget_set) == count

    def test_load_from_nonexistent_binary(self, gadget_set):
        with pytest.raises(FileNotFoundError):
            gadget_set.load_from_binary('/nonexistent/path/file.bin')

    def test_find_by_pattern(self, gadget_set, temp_binary):
        gadget_set.load_from_binary(temp_binary)
        results = gadget_set.find_by_pattern('mov')
        assert len(results) > 0
        assert all('mov' in g.instruction.lower() for g in results)

    def test_find_by_pattern_case_insensitive(self, gadget_set, temp_binary):
        gadget_set.load_from_binary(temp_binary)
        results_upper = gadget_set.find_by_pattern('MOV')
        results_lower = gadget_set.find_by_pattern('mov')
        assert len(results_upper) == len(results_lower)

    def test_find_by_register_write(self, gadget_set, temp_binary):
        gadget_set.load_from_binary(temp_binary)
        results = gadget_set.find_by_register_write('rax')
        assert len(results) > 0
        assert all(g.writes_register('rax') for g in results)

    def test_find_by_register_read(self, gadget_set, temp_binary):
        gadget_set.load_from_binary(temp_binary)
        results = gadget_set.find_by_register_read('rbx')
        assert len(results) > 0
        assert all(g.reads_register('rbx') for g in results)

    def test_find_by_effect(self, gadget_set, temp_binary):
        gadget_set.load_from_binary(temp_binary)
        results = gadget_set.find_by_effect('ret')
        assert len(results) > 0

    def test_get_statistics(self, gadget_set, temp_binary):
        gadget_set.load_from_binary(temp_binary)
        stats = gadget_set.get_statistics()
        assert 'total' in stats
        assert stats['total'] > 0
        assert 'by_type' in stats
        assert 'avg_instructions' in stats

    def test_iteration(self, gadget_set, temp_binary):
        gadget_set.load_from_binary(temp_binary)
        gadgets = list(gadget_set)
        assert len(gadgets) > 0
        assert all(isinstance(g, Gadget) for g in gadgets)

    def test_indexing(self, gadget_set, temp_binary):
        gadget_set.load_from_binary(temp_binary)
        gadget = gadget_set[0]
        assert isinstance(gadget, Gadget)


class TestOperand:
    def test_operand_is_register(self):
        op = Operand(OperandKind.REGISTER, 'rax')
        assert op.is_register()
        assert not op.is_immediate()
        assert not op.is_memory()

    def test_operand_is_immediate(self):
        op = Operand(OperandKind.IMMEDIATE, 0x100)
        assert op.is_immediate()
        assert not op.is_register()

    def test_operand_is_memory(self):
        op = Operand(OperandKind.MEMORY, 'rdi')
        assert op.is_memory()

    def test_operand_repr(self):
        op = Operand(OperandKind.REGISTER, 'rax')
        assert repr(op) == 'reg:rax'


class TestSemanticEffect:
    def test_effect_repr_simple(self):
        effect = SemanticEffect(effect_type='mov', destination='rax', source='rbx')
        assert 'mov' in repr(effect)
        assert 'rax' in repr(effect)

    def test_effect_repr_with_immediate(self):
        effect = SemanticEffect(effect_type='add', destination='rax', source='rbx', immediate=0x10)
        assert '0x10' in repr(effect)

    def test_effect_repr_with_offset(self):
        effect = SemanticEffect(effect_type='lea', destination='rax', source='rdi', offset=0x20)
        assert 'lea' in repr(effect)
