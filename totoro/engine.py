from z3 import *
import re
from typing import Dict, List, Optional, Tuple
from .gadget import Gadget, GadgetSet

class ConstraintEngine:
    def __init__(self):
        self.regs: Dict[str, BitVec] = {}
        self.memory: Dict[int, BitVec] = {}
        self.stack: List[BitVec] = []
        self._init_registers()
        
    def _init_registers(self):
        for reg in ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp',
                    'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']:
            self.regs[reg] = BitVec(reg, 64)
    
    def reset(self):
        self._init_registers()
        self.memory = {}
        self.stack = []
        
    def execute_gadget(self, gadget: Gadget, constraints: List) -> bool:
        if not gadget.semantic:
            return False
            
        sem = gadget.semantic
        
        if 'mov' in sem:
            dst, src = sem['mov']
            if dst in self.regs and src in self.regs:
                self.regs[dst] = self.regs[src]
                return True
            elif dst in self.regs and self._is_immediate(src):
                imm_val = self._parse_immediate(src)
                if imm_val is not None:
                    self.regs[dst] = BitVecVal(imm_val, 64)
                    return True
                    
        elif 'add' in sem:
            dst, src = sem['add']
            if dst in self.regs and src in self.regs:
                self.regs[dst] = self.regs[dst] + self.regs[src]
                return True
            elif dst in self.regs and self._is_immediate(src):
                imm_val = self._parse_immediate(src)
                if imm_val is not None:
                    self.regs[dst] = self.regs[dst] + BitVecVal(imm_val, 64)
                    return True
                
        elif 'pop' in sem:
            reg = sem['pop']
            if reg in self.regs and self.stack:
                self.regs[reg] = self.stack.pop()
                return True
                
        elif 'lea' in sem:
            dst, src = sem['lea']
            if dst in self.regs and '(' in src:
                match = re.match(r'([a-z0-9]+)\+?([0-9]*)\(([^)]+)\)', src)
                if match:
                    base = match.group(3)
                    offset = int(match.group(2)) if match.group(2) else 0
                    if base in self.regs:
                        self.regs[dst] = self.regs[base] + offset
                        return True
                        
        elif 'xchg' in sem:
            reg1, reg2 = sem['xchg']
            if reg1 in self.regs and reg2 in self.regs:
                temp = self.regs[reg1]
                self.regs[reg1] = self.regs[reg2]
                self.regs[reg2] = temp
                return True
                
        return False
    
    def _is_immediate(self, val: str) -> bool:
        val = val.strip()
        if val.startswith('0x'):
            return True
        if val.startswith('$'):
            return True
        try:
            int(val)
            return True
        except:
            return False
            
    def _parse_immediate(self, val: str) -> Optional[int]:
        val = val.strip()
        if val.startswith('0x'):
            try:
                return int(val, 16)
            except:
                return None
        if val.startswith('$'):
            try:
                return int(val[1:])
            except:
                return None
        try:
            return int(val)
        except:
            return None
            
    def parse_constraint(self, expr: str) -> Tuple[str, str, str, any]:
        expr = expr.strip()
        
        assign_match = re.match(r'(\w+)\s*=\s*(.+)', expr)
        if not assign_match:
            raise ValueError(f"Invalid constraint expression: {expr}")
            
        dst = assign_match.group(1)
        rhs = assign_match.group(2).strip()
        
        add_match = re.match(r'(.+?)\s*\+\s*(.+)', rhs)
        if add_match:
            src1 = add_match.group(1).strip()
            src2 = add_match.group(2).strip()
            
            val2 = self._parse_immediate(src2) or 0
            return (dst, 'add', src1, val2)
            
        func_match = re.match(r'(\w+)\s*\(\s*(.+?)\s*\)', rhs)
        if func_match:
            func_name = func_match.group(1)
            func_arg = func_match.group(2).strip()
            return (dst, func_name, func_arg, None)
            
        return (dst, 'mov', rhs, None)
        
    def get_register(self, name: str) -> Optional[BitVec]:
        name = name.lower().strip()
        if name.startswith('r') and name[1:] in ['ax', 'bx', 'cx', 'dx', 'si', 'di', 'bp', 'sp', 
                                                   '8', '9', '10', '11', '12', '13', '14', '15']:
            return self.regs.get(name)
        return self.regs.get(name)
        
    def set_register(self, name: str, value: BitVecRef):
        name = name.lower().strip()
        if name in self.regs:
            self.regs[name] = value
