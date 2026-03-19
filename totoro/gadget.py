from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import capstone

class OperandType(Enum):
    IMMEDIATE = "imm"
    REGISTER = "reg"
    MEMORY = "mem"

@dataclass
class Operand:
    type: OperandType
    value: any
    size: int = 8

@dataclass 
class Gadget:
    address: int
    instruction: str
    raw_bytes: bytes
    regs_read: list = field(default_factory=list)
    regs_write: list = field(default_factory=list)
    stack_adjust: int = 0
    semantic: Optional[dict] = None

    def __repr__(self):
        return f"Gadget(0x{self.address:x}: {self.instruction})"

class GadgetSet:
    def __init__(self):
        self.gadgets: list[Gadget] = []
        self._cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

    def load_from_binary(self, binary_path: str, max_gadgets: int = 10000):
        import struct
        
        try:
            with open(binary_path, 'rb') as f:
                data = f.read()
        except IOError:
            return

        for addr in range(0, len(data) - 15):
            for length in range(2, 16):
                if addr + length > len(data):
                    break
                    
                chunk = data[addr:addr + length]
                
                try:
                    for insn in self._cs.disasm(chunk, 0x400000 + addr):
                        if insn.mnemonic == 'ret':
                            gadget = self._parse_gadget(
                                0x400000 + addr, 
                                chunk[:length - 1], 
                                data[addr:addr + length]
                            )
                            if gadget:
                                self.gadgets.append(gadget)
                            break
                        elif insn.mnemonic.startswith('j') or insn.mnemonic == 'hlt':
                            break
                except:
                    continue
                    
                if len(self.gadgets) >= max_gadgets:
                    return

    def _parse_gadget(self, addr: int, code: bytes, full_bytes: bytes) -> Optional[Gadget]:
        instructions = list(self._cs.disasm(code, addr))
        if not instructions or instructions[-1].mnemonic != 'ret':
            return None
            
        last_insn = instructions[-1]
        
        regs_read = []
        regs_write = []
        stack_adj = 0
        
        for insn in instructions[:-1]:
            self._analyze_instruction(insn, regs_read, regs_write)
        
        if last_insn.mnemonic == 'ret':
            if len(last_insn.operands) > 0:
                try:
                    stack_adj = int(last_insn.operands[0])
                except:
                    stack_adj = 8
        
        instruction_text = "; ".join(
            f"{i.mnemonic} {i.op_str}" if i.op_str else i.mnemonic 
            for i in instructions
        )
        
        return Gadget(
            address=addr,
            instruction=instruction_text,
            raw_bytes=full_bytes,
            regs_read=regs_read,
            regs_write=regs_write,
            stack_adjust=stack_adj,
            semantic=self._extract_semantics(instructions)
        )

    def _analyze_instruction(self, insn, regs_read, regs_write):
        if hasattr(insn, 'regs_read') and insn.regs_read:
            regs_read.extend([r.name.lower() for r in insn.regs_read])
        if hasattr(insn, 'regs_write') and insn.regs_write:
            regs_write.extend([r.name.lower() for r in insn.regs_write])
            
        mnemonic = insn.mnemonic
        op_str = insn.op_str
        
        for reg in ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp', 
                    'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15',
                    'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp']:
            if reg in op_str:
                base_reg = reg[1:] if reg.startswith('r') and reg[1:] in ['ax', 'bx', 'cx', 'dx', 'si', 'di', 'bp', 'sp'] else reg
                if base_reg not in regs_read and base_reg not in regs_write:
                    if 'mov' in mnemonic or 'add' in mnemonic or 'lea' in mnemonic:
                        if '=' in mnemonic or 'xchg' in op_str:
                            if base_reg not in regs_write:
                                regs_write.append(base_reg)
                        else:
                            if base_reg not in regs_read:
                                regs_read.append(base_reg)

    def _extract_semantics(self, instructions):
        semantics = {}
        
        for insn in instructions:
            if insn.mnemonic == 'mov':
                parts = insn.op_str.split(',')
                if len(parts) == 2:
                    semantics['mov'] = (parts[0].strip(), parts[1].strip())
            elif insn.mnemonic == 'add':
                parts = insn.op_str.split(',')
                if len(parts) == 2:
                    semantics['add'] = (parts[0].strip(), parts[1].strip())
            elif insn.mnemonic == 'lea':
                parts = insn.op_str.split(',')
                if len(parts) == 2:
                    semantics['lea'] = (parts[0].strip(), parts[1].strip())
            elif insn.mnemonic == 'pop':
                semantics['pop'] = insn.op_str.strip()
            elif insn.mnemonic == 'xchg':
                parts = insn.op_str.split(',')
                if len(parts) == 2:
                    semantics['xchg'] = (parts[0].strip(), parts[1].strip())
                    
        return semantics if semantics else None

    def __len__(self):
        return len(self.gadgets)
    
    def __iter__(self):
        return iter(self.gadgets)
