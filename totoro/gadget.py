from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Set, List
import capstone


class OperandKind(Enum):
    IMMEDIATE = "imm"
    REGISTER = "reg"
    MEMORY = "mem"
    LABEL = "label"


@dataclass(frozen=True)
class Operand:
    kind: OperandKind
    value: any
    size: int = 8

    def is_register(self) -> bool:
        return self.kind == OperandKind.REGISTER

    def is_immediate(self) -> bool:
        return self.kind == OperandKind.IMMEDIATE

    def is_memory(self) -> bool:
        return self.kind == OperandKind.MEMORY

    def __repr__(self):
        return f"{self.kind.value}:{self.value}"


@dataclass
class Gadget:
    address: int
    raw_bytes: bytes
    instructions: List[str] = field(default_factory=list)
    regs_read: Set[str] = field(default_factory=set)
    regs_write: Set[str] = field(default_factory=set)
    stack_delta: int = 0
    memory_read: bool = False
    memory_write: bool = False
    branch: bool = False
    semantic: dict = field(default_factory=dict)

    @property
    def instruction(self) -> str:
        return "; ".join(self.instructions)

    @property
    def num_instructions(self) -> int:
        return len(self.instructions)

    @property
    def size(self) -> int:
        return len(self.raw_bytes)

    def reads_register(self, reg: str) -> bool:
        return reg.lower() in self.regs_read

    def writes_register(self, reg: str) -> bool:
        return reg.lower() in self.regs_write

    def __repr__(self):
        return f"<Gadget 0x{self.address:x}: {self.instruction[:50]}>"

    def __hash__(self):
        return hash(self.address)

    def __eq__(self, other):
        if not isinstance(other, Gadget):
            return False
        return self.address == other.address


@dataclass
class SemanticEffect:
    effect_type: str
    destination: Optional[str] = None
    source: Optional[str] = None
    offset: int = 0
    immediate: Optional[int] = None

    def __repr__(self):
        if self.immediate is not None:
            return f"{self.effect_type} {self.destination} = {self.source} + 0x{self.immediate:x}"
        if self.offset:
            return f"{self.effect_type} {self.destination} = [{self.source} + 0x{self.offset:x}]"
        if self.source:
            return f"{self.effect_type} {self.destination} = {self.source}"
        return f"{self.effect_type} {self.destination}"


class GadgetLifter:
    def __init__(self, base_address: int = 0x400000):
        self.base_address = base_address
        self._cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self._cs.detail = True

    def lift(self, address: int, code: bytes) -> Optional[Gadget]:
        instructions = list(self._cs.disasm(code, address))
        if not instructions:
            return None

        if instructions[-1].mnemonic != 'ret':
            return None

        gadget = Gadget(
            address=address,
            raw_bytes=code,
            instructions=[]
        )

        regs_read: Set[str] = set()
        regs_write: Set[str] = set()
        effects: List[SemanticEffect] = []
        stack_delta = 0

        for insn in instructions:
            gadget.instructions.append(
                f"{insn.mnemonic} {insn.op_str}" if insn.op_str else insn.mnemonic
            )

            self._analyze_register_operands(insn, regs_read, regs_write)

            effect = self._extract_semantic_effect(insn)
            if effect:
                effects.append(effect)

            if insn.mnemonic in ('push', 'call'):
                stack_delta -= 8
            elif insn.mnemonic == 'pop':
                stack_delta += 8
            elif insn.mnemonic == 'ret':
                try:
                    if insn.operands and len(insn.operands) > 0:
                        stack_delta += 8
                    else:
                        stack_delta += 8
                except:
                    stack_delta += 8
            elif insn.mnemonic in ('sub', 'add'):
                try:
                    ops = insn.op_str.split(',')
                    if len(ops) == 2 and 'rsp' in ops[0].lower():
                        imm_str = ops[1].strip()
                        if imm_str.startswith('0x'):
                            imm_val = int(imm_str, 16)
                        else:
                            imm_val = int(imm_str)
                        if insn.mnemonic == 'sub':
                            stack_delta -= imm_val
                        else:
                            stack_delta += imm_val
                except:
                    pass

            if insn.mnemonic in ('mov', 'movzx', 'movabs'):
                gadget.memory_read = gadget.memory_read or '[' in insn.op_str
            elif insn.mnemonic in ('call', 'jmp') and not insn.mnemonic.startswith('j'):
                gadget.branch = True

        gadget.regs_read = regs_read
        gadget.regs_write = regs_write
        gadget.stack_delta = stack_delta

        semantic = {}
        for effect in effects:
            if effect.effect_type not in semantic:
                if effect.effect_type in ('mov', 'add', 'sub', 'lea', 'xchg'):
                    key = effect.effect_type
                    if effect.source is None and effect.immediate is not None:
                        semantic[key] = (effect.destination, str(effect.immediate))
                    elif effect.source is not None and effect.immediate is not None:
                        semantic[key] = (effect.destination, f"{effect.source}+0x{effect.immediate:x}")
                    else:
                        semantic[key] = (effect.destination, effect.source)
                elif effect.effect_type == 'pop':
                    semantic['pop'] = effect.destination
                elif effect.effect_type == 'xor_zero':
                    semantic['xor_zero'] = effect.destination
        gadget.semantic = semantic

        return gadget

    def _analyze_register_operands(self, insn, regs_read: Set[str], regs_write: Set[str]):
        if hasattr(insn, 'regs_read') and insn.regs_read:
            for r in insn.regs_read:
                regs_read.add(r.name.lower())

        if hasattr(insn, 'regs_write') and insn.regs_write:
            for r in insn.regs_write:
                regs_write.add(r.name.lower())

        op_str = insn.op_str.lower()
        all_regs = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp',
                    'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15',
                    'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp',
                    'ax', 'bx', 'cx', 'dx', 'si', 'di', 'bp', 'sp',
                    'al', 'ah', 'bl', 'bh', 'cl', 'ch', 'dl', 'dh']

        for reg in all_regs:
            if reg in op_str:
                base = self._normalize_register(reg)
                if base:
                    if insn.mnemonic in ('mov', 'lea', 'pop', 'xchg'):
                        if '=' in insn.op_str or reg in insn.op_str.split(',')[0].lower():
                            regs_write.add(base)
                        else:
                            regs_read.add(base)
                    else:
                        regs_read.add(base)

    def _normalize_register(self, reg: str) -> Optional[str]:
        full_regs = {
            'rax': 'rax', 'eax': 'rax', 'ax': 'rax', 'al': 'rax', 'ah': 'rax',
            'rbx': 'rbx', 'ebx': 'rbx', 'bx': 'rbx', 'bl': 'rbx', 'bh': 'rbx',
            'rcx': 'rcx', 'ecx': 'rcx', 'cx': 'rcx', 'cl': 'rcx', 'ch': 'rcx',
            'rdx': 'rdx', 'edx': 'rdx', 'dx': 'rdx', 'dl': 'rdx', 'dh': 'rdx',
            'rsi': 'rsi', 'esi': 'rsi', 'si': 'rsi',
            'rdi': 'rdi', 'edi': 'rdi', 'di': 'rdi',
            'rbp': 'rbp', 'ebp': 'rbp', 'bp': 'rbp',
            'rsp': 'rsp', 'esp': 'rsp', 'sp': 'rsp',
            'r8': 'r8', 'r9': 'r9', 'r10': 'r10', 'r11': 'r11',
            'r12': 'r12', 'r13': 'r13', 'r14': 'r14', 'r15': 'r15',
        }
        return full_regs.get(reg.lower())

    def _extract_semantic_effect(self, insn) -> Optional[SemanticEffect]:
        mnemonic = insn.mnemonic
        op_str = insn.op_str.strip() if insn.op_str else ""

        if mnemonic == 'mov' or mnemonic == 'movzx' or mnemonic == 'movabs':
            parts = op_str.split(',')
            if len(parts) == 2:
                dst = parts[0].strip().lower()
                src = parts[1].strip().lower()
                dst = self._normalize_register(dst) or dst
                src = self._normalize_register(src) or src
                return SemanticEffect(effect_type='mov', destination=dst, source=src)

        elif mnemonic == 'lea':
            parts = op_str.split(',')
            if len(parts) == 2:
                dst = parts[0].strip().lower()
                src = parts[1].strip()
                dst = self._normalize_register(dst) or dst
                match = re.match(r'([a-z0-9]+)\+?([0-9]*)\(([^)]+)\)', src)
                if match:
                    base = match.group(3).lower()
                    offset = int(match.group(2)) if match.group(2) else 0
                    return SemanticEffect(effect_type='lea', destination=dst, source=base, offset=offset)

        elif mnemonic == 'add':
            parts = op_str.split(',')
            if len(parts) == 2:
                dst = parts[0].strip().lower()
                src = parts[1].strip()
                dst = self._normalize_register(dst) or dst
                src_norm = self._normalize_register(src) or src
                imm = None
                if src.startswith('0x') or src.isdigit():
                    try:
                        imm = int(src, 16) if src.startswith('0x') else int(src)
                        src_norm = None
                    except:
                        pass
                return SemanticEffect(effect_type='add', destination=dst, source=src_norm, immediate=imm)

        elif mnemonic == 'sub':
            parts = op_str.split(',')
            if len(parts) == 2:
                dst = parts[0].strip().lower()
                src = parts[1].strip()
                dst = self._normalize_register(dst) or dst
                src_norm = self._normalize_register(src) or src
                imm = None
                if src.startswith('0x') or src.isdigit():
                    try:
                        imm = int(src, 16) if src.startswith('0x') else int(src)
                        src_norm = None
                    except:
                        pass
                return SemanticEffect(effect_type='sub', destination=dst, source=src_norm, immediate=imm)

        elif mnemonic == 'pop':
            reg = self._normalize_register(op_str.lower()) or op_str.lower()
            return SemanticEffect(effect_type='pop', destination=reg)

        elif mnemonic == 'xchg':
            parts = op_str.split(',')
            if len(parts) == 2:
                reg1 = self._normalize_register(parts[0].strip().lower()) or parts[0].strip().lower()
                reg2 = self._normalize_register(parts[1].strip().lower()) or parts[1].strip().lower()
                return SemanticEffect(effect_type='xchg', destination=reg1, source=reg2)

        elif mnemonic == 'xor':
            parts = op_str.split(',')
            if len(parts) == 2:
                dst = parts[0].strip().lower()
                src = parts[1].strip()
                if dst == src:
                    return SemanticEffect(effect_type='xor_zero', destination=dst, source=src)

        return None


import re


class GadgetSet:
    def __init__(self, base_address: int = 0x400000, max_gadgets: int = 50000):
        self.base_address = base_address
        self.max_gadgets = max_gadgets
        self._lifter = GadgetLifter(base_address)
        self.gadgets: List[Gadget] = []
        self._by_address: dict = {}

    def load_from_binary(self, binary_path: str) -> int:
        try:
            with open(binary_path, 'rb') as f:
                data = f.read()
        except IOError as e:
            raise FileNotFoundError(f"Cannot read binary: {binary_path}") from e

        self.gadgets.clear()
        self._by_address.clear()

        ret_byte = 0xc3
        nop_byte = 0x90
        int3_byte = 0xcc

        for i in range(len(data) - 1):
            if data[i] == ret_byte:
                for gadget_len in range(2, 20):
                    start = i - gadget_len + 1
                    if start < 0:
                        break

                    chunk = data[start:i + 1]

                    if any(b in chunk[:gadget_len-1] for b in (int3_byte,)):
                        continue

                    try:
                        addr = self.base_address + start
                        gadget = self._lifter.lift(addr, chunk)

                        if gadget and gadget.num_instructions >= 1:
                            code_bytes = data[start:min(i + 2, len(data))]
                            gadget.raw_bytes = code_bytes

                            if addr not in self._by_address:
                                self.gadgets.append(gadget)
                                self._by_address[addr] = gadget
                                break
                    except Exception:
                        continue

                if len(self.gadgets) >= self.max_gadgets:
                    break

        return len(self.gadgets)

    def find_by_pattern(self, pattern: str) -> List[Gadget]:
        pattern_lower = pattern.lower()
        return [g for g in self.gadgets if pattern_lower in g.instruction.lower()]

    def find_by_register_write(self, reg: str) -> List[Gadget]:
        reg = reg.lower()
        return [g for g in self.gadgets if g.writes_register(reg)]

    def find_by_register_read(self, reg: str) -> List[Gadget]:
        reg = reg.lower()
        return [g for g in self.gadgets if g.reads_register(reg)]

    def find_by_effect(self, effect_type: str) -> List[Gadget]:
        return [g for g in self.gadgets if effect_type in g.instruction.lower()]

    def get_statistics(self) -> dict:
        stats = {
            'total': len(self.gadgets),
            'by_type': {},
            'by_stack_delta': {},
            'with_memory_ops': 0,
            'avg_instructions': 0,
        }

        type_counts = {}
        delta_counts = {}
        total_instructions = 0
        memory_count = 0

        for g in self.gadgets:
            mnemonic = g.instructions[0].split()[0] if g.instructions else 'unknown'
            type_counts[mnemonic] = type_counts.get(mnemonic, 0) + 1

            delta_key = g.stack_delta
            delta_counts[delta_key] = delta_counts.get(delta_key, 0) + 1

            total_instructions += g.num_instructions
            if g.memory_read or g.memory_write:
                memory_count += 1

        stats['by_type'] = type_counts
        stats['by_stack_delta'] = delta_counts
        stats['with_memory_ops'] = memory_count
        stats['avg_instructions'] = total_instructions / len(self.gadgets) if self.gadgets else 0

        return stats

    def __len__(self):
        return len(self.gadgets)

    def __iter__(self):
        return iter(self.gadgets)

    def __getitem__(self, index: int) -> Gadget:
        return self.gadgets[index]
