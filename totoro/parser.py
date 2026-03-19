import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Union


class OperationType(Enum):
    MOV = "mov"
    ADD = "add"
    SUB = "sub"
    READ = "read"
    WRITE = "write"
    LEA = "lea"
    XOR = "xor"
    AND = "and"
    OR = "or"


@dataclass
class ConstraintOperand:
    kind: str
    value: str
    offset: int = 0

    def __repr__(self):
        if self.offset:
            return f"{self.kind}:{self.value}+0x{self.offset:x}"
        return f"{self.kind}:{self.value}"


@dataclass
class ParsedConstraint:
    target: str
    operation: OperationType
    source1: ConstraintOperand
    source2: Optional[ConstraintOperand] = None
    immediate: Optional[int] = None

    def __repr__(self):
        parts = [f"target={self.target}", f"op={self.operation.value}"]
        parts.append(f"src1={self.source1}")
        if self.source2:
            parts.append(f"src2={self.source2}")
        if self.immediate is not None:
            parts.append(f"imm=0x{self.immediate:x}")
        return f"Constraint({', '.join(parts)})"


class ParseError(Exception):
    pass


class ConstraintParser:
    REGISTER_PATTERN = r'\b(rax|rbx|rcx|rdx|rsi|rdi|rbp|rsp|r8|r9|r10|r11|r12|r13|r14|r15|eax|ebx|ecx|edx|esi|edi|ebp|esp|r8d|r9d|r10d|r11d|r12d|r13d|r14d|r15d)\b'
    IMMEDIATE_PATTERN = r'(?:0x[0-9a-fA-F]+|[0-9]+)'

    def __init__(self):
        self._register_re = re.compile(self.REGISTER_PATTERN)

    def parse(self, expr: str) -> ParsedConstraint:
        expr = expr.strip()
        if not expr:
            raise ParseError("Empty constraint expression")

        if '=' not in expr:
            raise ParseError(f"Missing assignment operator in: {expr}")

        parts = expr.split('=', 1)
        if len(parts) != 2:
            raise ParseError(f"Invalid assignment format: {expr}")

        target = parts[0].strip()
        if not target:
            raise ParseError("Missing target register")
        if not self._is_register(target):
            raise ParseError(f"Target must be a register, got: {target}")

        rhs = parts[1].strip()

        return self._parse_rhs(target, rhs)

    def _parse_rhs(self, target: str, rhs: str) -> ParsedConstraint:
        rhs = rhs.strip()

        func_with_add_match = re.match(r'(\w+)\s*\(\s*(\[?.*?\]?)\s*\)\s*\+\s*(.+)$', rhs)
        if func_with_add_match:
            func_name = func_with_add_match.group(1)
            inner_arg = func_with_add_match.group(2)
            add_part = func_with_add_match.group(3)
            base_constraint = self._parse_function(target, func_name, inner_arg)
            add_operand = self._parse_operand(add_part.strip())
            imm = None
            if add_operand.kind == 'immediate':
                imm = add_operand.value
            return ParsedConstraint(
                target=target,
                operation=OperationType.ADD,
                source1=base_constraint.source1,
                immediate=imm
            )

        func_match = re.match(r'(\w+)\s*\(\s*(.+?)\s*\)\s*$', rhs)
        if func_match:
            func_name = func_match.group(1)
            arg = func_match.group(2)
            if func_name.lower() in ('lea', 'xor'):
                if '-' in arg:
                    parts = arg.split('-', 1)
                    if len(parts) == 2:
                        src1 = self._parse_operand(parts[0].strip())
                        src2 = self._parse_operand(parts[1].strip())
                        imm = None
                        if src2.kind == 'immediate':
                            imm = -src2.value
                            src2 = None
                        return ParsedConstraint(
                            target=target,
                            operation=OperationType.LEA if func_name.lower() == 'lea' else OperationType.XOR,
                            source1=src1,
                            source2=src2,
                            immediate=imm
                        )
            return self._parse_function(target, func_name, arg)

        if '+' in rhs:
            return self._parse_addition(target, rhs)

        if '-' in rhs:
            return self._parse_subtraction(target, rhs)

        return self._parse_simple(target, rhs)

    def _parse_addition(self, target: str, rhs: str) -> ParsedConstraint:
        parts = rhs.split('+', 1)
        if len(parts) != 2:
            raise ParseError(f"Invalid addition syntax: {rhs}")

        src1_raw = parts[0].strip()
        src2_raw = parts[1].strip()

        src1 = self._parse_operand(src1_raw)
        src2 = self._parse_operand(src2_raw)

        imm = None
        if src2.kind == 'immediate':
            imm = src2.value
            src2 = None

        return ParsedConstraint(
            target=target,
            operation=OperationType.ADD,
            source1=src1,
            source2=src2,
            immediate=imm
        )

    def _parse_subtraction(self, target: str, rhs: str) -> ParsedConstraint:
        parts = rhs.split('-', 1)
        if len(parts) != 2:
            raise ParseError(f"Invalid subtraction syntax: {rhs}")

        src1_raw = parts[0].strip()
        src2_raw = parts[1].strip()

        src1 = self._parse_operand(src1_raw)
        src2 = self._parse_operand(src2_raw)

        imm = None
        if src2.kind == 'immediate':
            imm = -src2.value
            src2 = None

        return ParsedConstraint(
            target=target,
            operation=OperationType.SUB,
            source1=src1,
            source2=src2,
            immediate=imm
        )

    def _parse_function(self, target: str, func_name: str, arg: str) -> ParsedConstraint:
        func_name = func_name.lower()

        if func_name == 'read':
            op = OperationType.READ
        elif func_name == 'write':
            op = OperationType.WRITE
        elif func_name == 'lea':
            op = OperationType.LEA
        elif func_name == 'xor':
            op = OperationType.XOR
        else:
            raise ParseError(f"Unknown function: {func_name}")

        if func_name in ('read', 'write'):
            operand = self._parse_memory_operand(arg)
        else:
            operand = self._parse_operand(arg)

        return ParsedConstraint(
            target=target,
            operation=op,
            source1=operand
        )

    def _parse_simple(self, target: str, rhs: str) -> ParsedConstraint:
        operand = self._parse_operand(rhs)

        if operand.kind == 'immediate':
            return ParsedConstraint(
                target=target,
                operation=OperationType.MOV,
                source1=operand
            )

        return ParsedConstraint(
            target=target,
            operation=OperationType.MOV,
            source1=operand
        )

    def _parse_operand(self, raw: str) -> ConstraintOperand:
        raw = raw.strip()

        mem_match = re.match(r'\[([^\]]+)\]', raw)
        if mem_match:
            inner = mem_match.group(1).strip()
            parts = inner.split('+')
            base = parts[0].strip()
            offset = 0
            if len(parts) > 1:
                try:
                    offset_str = parts[1].strip()
                    if offset_str.startswith('0x'):
                        offset = int(offset_str, 16)
                    else:
                        offset = int(offset_str)
                except ValueError:
                    pass
            return ConstraintOperand(kind='memory', value=base, offset=offset)

        if raw.startswith('0x') or raw.isdigit() or (raw.startswith('-') and raw[1:].isdigit()):
            try:
                if raw.startswith('0x'):
                    val = int(raw, 16)
                else:
                    val = int(raw)
                return ConstraintOperand(kind='immediate', value=val)
            except ValueError:
                pass

        if self._is_register(raw):
            return ConstraintOperand(kind='register', value=raw)

        raise ParseError(f"Unknown operand: {raw}")

    def _is_register(self, token: str) -> bool:
        token = token.lower().strip()
        return bool(re.match(r'^' + self.REGISTER_PATTERN + r'$', token))

    def _parse_memory_operand(self, arg: str) -> ConstraintOperand:
        arg = arg.strip()
        if self._is_register(arg):
            return ConstraintOperand(kind='memory', value=arg.lower())
        mem_match = re.match(r'\[([^\]]+)\]', arg)
        if mem_match:
            inner = mem_match.group(1).strip()
            parts = inner.split('+')
            base = parts[0].strip()
            offset = 0
            if len(parts) > 1:
                try:
                    offset_str = parts[1].strip()
                    if offset_str.startswith('0x'):
                        offset = int(offset_str, 16)
                    else:
                        offset = int(offset_str)
                except ValueError:
                    pass
            return ConstraintOperand(kind='memory', value=base, offset=offset)
        if '+' in arg:
            parts = arg.split('+')
            if len(parts) == 2 and self._is_register(parts[0].strip()):
                base = parts[0].strip()
                offset_str = parts[1].strip()
                offset = 0
                try:
                    if offset_str.startswith('0x'):
                        offset = int(offset_str, 16)
                    else:
                        offset = int(offset_str)
                except ValueError:
                    pass
                return ConstraintOperand(kind='memory', value=base.lower(), offset=offset)
        raise ParseError(f"Unknown memory operand: {arg}")

    def tokenize(self, expr: str) -> list[str]:
        tokens = []
        current = ""
        in_brackets = False

        for ch in expr:
            if ch == '[':
                if current.strip():
                    stripped = current.strip()
                    if stripped.endswith('('):
                        tokens.append(stripped[:-1])
                    else:
                        tokens.append(stripped)
                    current = ""
                current += ch
                in_brackets = True
            elif ch == ']':
                current += ch
                tokens.append(current.strip())
                current = ""
                in_brackets = False
            elif ch in '+-' and in_brackets:
                if current.strip():
                    tokens.append(current.strip())
                tokens.append(ch)
                current = ""
            elif ch == ')' and not in_brackets:
                if current.strip():
                    tokens.append(current.strip())
                    current = ""
                tokens.append(ch)
            elif ch in ' \t' and not in_brackets:
                if current.strip():
                    tokens.append(current.strip())
                    current = ""
            else:
                current += ch

        if current.strip():
            tokens.append(current.strip())

        return [t for t in tokens if t]


def parse_constraint(expr: str) -> ParsedConstraint:
    parser = ConstraintParser()
    return parser.parse(expr)
