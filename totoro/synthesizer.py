from .engine import ConstraintEngine
from .gadget import GadgetSet, Gadget
from typing import List, Optional, Tuple
import re

class SynthesizedChain:
    def __init__(self):
        self.gadgets: List[Gadget] = []
        self.registers: dict = {}
        
    def add_gadget(self, gadget: Gadget):
        self.gadgets.append(gadget)
        
    def __repr__(self):
        lines = ["ROP Chain:"]
        for i, g in enumerate(self.gadgets):
            lines.append(f"  [{i}] 0x{g.address:x}: {g.instruction}")
        return "\n".join(lines)

class Synthesizer:
    def __init__(self):
        self.engine = ConstraintEngine()
        self.gadget_set: Optional[GadgetSet] = None
        
    def load_binary(self, binary_path: str):
        self.gadget_set = GadgetSet()
        self.gadget_set.load_from_binary(binary_path)
        return len(self.gadget_set)
        
    def synthesize(self, constraint_expr: str, max_gadgets: int = 10) -> Optional[SynthesizedChain]:
        if not self.gadget_set:
            return None
            
        try:
            dst, op, src, imm = self.engine.parse_constraint(constraint_expr)
        except ValueError as e:
            print(f"Parse error: {e}")
            return None
            
        chains = self._find_chains(dst, op, src, imm, max_gadgets)
        
        if chains:
            return chains[0]
        return None
        
    def _find_chains(self, dst: str, op: str, src: str, imm: any, max_len: int) -> List[SynthesizedChain]:
        chains = []
        
        for gadget in self.gadget_set.gadgets:
            if not gadget.semantic:
                continue
                
            chain = SynthesizedChain()
            self.engine.reset()
            
            if self._apply_gadget_effects(chain, gadget, dst, op, src, imm):
                chains.append(chain)
                if len(chains) >= 5:
                    break
                    
        return chains
        
    def _apply_gadget_effects(self, chain: SynthesizedChain, gadget: Gadget, 
                                dst: str, op: str, src: str, imm: any) -> bool:
        sem = gadget.semantic
        
        if op == 'mov' and 'mov' in sem:
            sem_dst, sem_src = sem['mov']
            if sem_dst == dst:
                if sem_src == src or (src in self.engine.regs and 
                                      self._regs_match(sem_src, src)):
                    chain.add_gadget(gadget)
                    self.engine.execute_gadget(gadget, [])
                    return True
                    
        elif op == 'add' and 'add' in sem:
            sem_dst, sem_src = sem['add']
            if sem_dst == dst:
                if imm is not None:
                    sem_imm = self.engine._parse_immediate(sem_src)
                    if sem_imm is not None and sem_imm == imm:
                        chain.add_gadget(gadget)
                        self.engine.execute_gadget(gadget, [])
                        return True
                elif src in self.engine.regs and self._regs_match(sem_src, src):
                    chain.add_gadget(gadget)
                    self.engine.execute_gadget(gadget, [])
                    return True
                        
        elif op in ['read', 'write', 'call'] and 'lea' in sem:
            sem_dst, sem_src = sem['lea']
            if sem_dst == dst:
                if self._memory_access_match(sem_src, src, op):
                    chain.add_gadget(gadget)
                    self.engine.execute_gadget(gadget, [])
                    return True
                    
        elif op == 'read' and 'mov' in sem:
            sem_dst, sem_src = sem['mov']
            if sem_dst == dst and '[' in sem_src:
                chain.add_gadget(gadget)
                self.engine.execute_gadget(gadget, [])
                return True
                
        return False
        
    def _regs_match(self, reg1: str, reg2: str) -> bool:
        reg1 = reg1.lower().strip()
        reg2 = reg2.lower().strip()
        return reg1 == reg2
        
    def _imms_compatible(self, src: str, target_imm: any) -> bool:
        if isinstance(target_imm, int):
            return True
        return False
        
    def _memory_access_match(self, mem_expr: str, arg: str, access_type: str) -> bool:
        if arg in mem_expr:
            return True
        if '+' in mem_expr and arg.split('+')[0].strip() in mem_expr:
            return True
        return False
        
    def find_gadget(self, pattern: str) -> List[Gadget]:
        if not self.gadget_set:
            return []
            
        results = []
        pattern_lower = pattern.lower()
        
        for gadget in self.gadget_set.gadgets:
            if pattern_lower in gadget.instruction.lower():
                results.append(gadget)
                
        return results[:50]
        
    def get_statistics(self) -> dict:
        if self.gadget_set is None:
            return {}
            
        return {
            "total_gadgets": len(self.gadget_set),
            "by_type": self._count_by_type()
        }
        
    def _count_by_type(self) -> dict:
        counts = {'mov': 0, 'add': 0, 'pop': 0, 'lea': 0, 'xchg': 0, 'other': 0}
        
        if not self.gadget_set:
            return counts
            
        for g in self.gadget_set.gadgets:
            if not g.semantic:
                counts['other'] += 1
            else:
                found = False
                for key in ['mov', 'add', 'pop', 'lea', 'xchg']:
                    if key in g.semantic:
                        counts[key] += 1
                        found = True
                        break
                if not found:
                    counts['other'] += 1
                    
        return counts
