import pytest
from totoro.parser import (
    ConstraintParser,
    parse_constraint,
    OperationType,
    ConstraintOperand,
    ParsedConstraint,
    ParseError
)


class TestConstraintParser:
    def test_simple_register_assignment(self, parser):
        result = parser.parse('rax = rbx')
        assert result.target == 'rax'
        assert result.operation == OperationType.MOV
        assert result.source1.kind == 'register'
        assert result.source1.value == 'rbx'
        assert result.source2 is None
        assert result.immediate is None

    def test_immediate_hex(self, parser):
        result = parser.parse('rax = 0x100')
        assert result.target == 'rax'
        assert result.operation == OperationType.MOV
        assert result.source1.kind == 'immediate'
        assert result.source1.value == 0x100

    def test_immediate_decimal(self, parser):
        result = parser.parse('rax = 256')
        assert result.target == 'rax'
        assert result.operation == OperationType.MOV
        assert result.source1.kind == 'immediate'
        assert result.source1.value == 256

    def test_addition_register_immediate(self, parser):
        result = parser.parse('rax = rax + 0x100')
        assert result.target == 'rax'
        assert result.operation == OperationType.ADD
        assert result.source1.kind == 'register'
        assert result.source1.value == 'rax'
        assert result.immediate == 0x100

    def test_addition_decimal(self, parser):
        result = parser.parse('rax = rax + 16')
        assert result.target == 'rax'
        assert result.operation == OperationType.ADD
        assert result.immediate == 16

    def test_subtraction(self, parser):
        result = parser.parse('rax = rax - 8')
        assert result.target == 'rax'
        assert result.operation == OperationType.SUB
        assert result.immediate == -8

    def test_memory_read_simple(self, parser):
        result = parser.parse('rax = read(rdi)')
        assert result.target == 'rax'
        assert result.operation == OperationType.READ
        assert result.source1.kind == 'memory'
        assert result.source1.value == 'rdi'
        assert result.source1.offset == 0

    def test_memory_read_with_offset(self, parser):
        result = parser.parse('rax = read(rdi + 0x20)')
        assert result.target == 'rax'
        assert result.operation == OperationType.READ
        assert result.source1.kind == 'memory'
        assert result.source1.value == 'rdi'
        assert result.source1.offset == 0x20

    def test_memory_write(self, parser):
        result = parser.parse('rax = write(rsi)')
        assert result.target == 'rax'
        assert result.operation == OperationType.WRITE
        assert result.source1.kind == 'memory'
        assert result.source1.value == 'rsi'

    def test_lea_operation(self, parser):
        result = parser.parse('rax = lea(rbp - 8)')
        assert result.target == 'rax'
        assert result.operation == OperationType.LEA

    def test_xor_operation(self, parser):
        result = parser.parse('rax = xor(rbx)')
        assert result.target == 'rax'
        assert result.operation == OperationType.XOR

    def test_complex_expression(self, parser):
        result = parser.parse('rax = read(rdi + 0x20) + 0x100')
        assert result.target == 'rax'
        assert result.operation == OperationType.ADD
        assert result.source1.kind == 'memory'
        assert result.source1.value == 'rdi'
        assert result.source1.offset == 0x20
        assert result.immediate == 0x100

    def test_whitespace_handling(self, parser):
        result = parser.parse('  rax   =   rbx  ')
        assert result.target == 'rax'
        assert result.source1.value == 'rbx'

    def test_case_insensitive_register(self, parser):
        result = parser.parse('RAX = RBX')
        assert result.target == 'RAX'
        assert result.source1.value == 'RBX'


class TestParseErrors:
    def test_empty_expression(self, parser):
        with pytest.raises(ParseError, match="Empty constraint expression"):
            parser.parse('')

    def test_empty_after_strip(self, parser):
        with pytest.raises(ParseError):
            parser.parse('   ')

    def test_missing_equals(self, parser):
        with pytest.raises(ParseError, match="Missing assignment operator"):
            parser.parse('rax rbx')

    def test_invalid_target_register(self, parser):
        with pytest.raises(ParseError, match="Target must be a register"):
            parser.parse('notreg = rbx')

    def test_invalid_operand(self, parser):
        with pytest.raises(ParseError, match="Unknown operand"):
            parser.parse('rax = invalid')

    def test_unknown_function(self, parser):
        with pytest.raises(ParseError, match="Unknown function"):
            parser.parse('rax = foobar(rbx)')


class TestTokenize:
    def test_tokenize_simple(self, parser):
        tokens = parser.tokenize('rax = rbx')
        assert 'rax' in tokens
        assert '=' in tokens
        assert 'rbx' in tokens

    def test_tokenize_memory(self, parser):
        tokens = parser.tokenize('rax = read([rdi + 0x20])')
        assert 'read' in tokens
        assert '[rdi' in tokens
        assert '+' in tokens
        assert '0x20]' in tokens


class TestModuleFunction:
    def test_parse_constraint_function(self):
        result = parse_constraint('rax = rbx + 0x100')
        assert result.target == 'rax'
        assert result.operation == OperationType.ADD


class TestConstraintOperand:
    def test_repr_no_offset(self):
        op = ConstraintOperand(kind='register', value='rax')
        assert repr(op) == 'register:rax'

    def test_repr_with_offset(self):
        op = ConstraintOperand(kind='memory', value='rdi', offset=0x20)
        assert 'rdi' in repr(op)
        assert '0x20' in repr(op)


class TestParsedConstraint:
    def test_repr(self):
        parser = ConstraintParser()
        result = parser.parse('rax = rbx + 0x10')
        repr_str = repr(result)
        assert 'target=rax' in repr_str
        assert 'op=add' in repr_str
