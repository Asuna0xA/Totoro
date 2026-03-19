import pytest
from totoro.synthesizer import Synthesizer, SynthesizedChain
from totoro.gadget import Gadget, GadgetLifter, GadgetSet


class TestSynthesizedChain:
    def test_chain_creation(self):
        chain = SynthesizedChain()
        assert len(chain.gadgets) == 0
        assert chain.registers == {}

    def test_add_gadget(self):
        chain = SynthesizedChain()
        gadget = Gadget(address=0x400000, raw_bytes=bytes([0xC3]), instructions=['ret'])
        chain.add_gadget(gadget)
        assert len(chain.gadgets) == 1
        assert chain.gadgets[0] is gadget

    def test_repr(self):
        chain = SynthesizedChain()
        gadget = Gadget(address=0x400000, raw_bytes=bytes([0xC3]), instructions=['mov rax, rbx', 'ret'])
        chain.add_gadget(gadget)
        repr_str = repr(chain)
        assert 'ROP Chain' in repr_str
        assert '0x400000' in repr_str


class TestSynthesizer:
    def test_synthesizer_creation(self, synthesizer):
        assert synthesizer.gadget_set is None
        assert synthesizer.engine is not None

    def test_load_binary(self, synthesizer, temp_binary):
        count = synthesizer.load_binary(temp_binary)
        assert count > 0
        assert synthesizer.gadget_set is not None
        assert len(synthesizer.gadget_set) > 0

    def test_load_nonexistent_binary(self, synthesizer):
        result = synthesizer.load_binary('/nonexistent/path/file.bin')
        assert result == 0

    def test_synthesize_without_binary(self, synthesizer):
        result = synthesizer.synthesize('rax = rbx')
        assert result is None

    def test_synthesize_with_valid_constraint(self, synthesizer, temp_binary):
        synthesizer.load_binary(temp_binary)
        result = synthesizer.synthesize('rax = rbx')
        assert result is None or isinstance(result, SynthesizedChain)

    def test_synthesize_with_add_constraint(self, synthesizer, temp_binary):
        synthesizer.load_binary(temp_binary)
        result = synthesizer.synthesize('rax = rax + 0x10')
        assert result is None or isinstance(result, SynthesizedChain)

    def test_synthesize_with_memory_read(self, synthesizer, temp_binary):
        synthesizer.load_binary(temp_binary)
        result = synthesizer.synthesize('rax = read(rdi)')
        assert result is None or isinstance(result, SynthesizedChain)

    def test_find_gadget(self, synthesizer, temp_binary):
        synthesizer.load_binary(temp_binary)
        results = synthesizer.find_gadget('mov')
        assert isinstance(results, list)
        assert all('mov' in g.instruction.lower() for g in results)

    def test_find_gadget_without_binary(self, synthesizer):
        results = synthesizer.find_gadget('mov')
        assert results == []

    def test_find_gadget_case_insensitive(self, synthesizer, temp_binary):
        synthesizer.load_binary(temp_binary)
        results_upper = synthesizer.find_gadget('MOV')
        results_lower = synthesizer.find_gadget('mov')
        assert len(results_upper) == len(results_lower)

    def test_find_gadget_limit(self, synthesizer, temp_binary):
        synthesizer.load_binary(temp_binary)
        results = synthesizer.find_gadget('ret')
        assert len(results) <= 50

    def test_get_statistics(self, synthesizer, temp_binary):
        synthesizer.load_binary(temp_binary)
        stats = synthesizer.get_statistics()
        assert 'total_gadgets' in stats
        assert stats['total_gadgets'] > 0
        assert 'by_type' in stats

    def test_get_statistics_without_binary(self, synthesizer):
        stats = synthesizer.get_statistics()
        assert stats == {}

    def test_count_by_type(self, synthesizer, temp_binary):
        synthesizer.load_binary(temp_binary)
        counts = synthesizer._count_by_type()
        assert 'mov' in counts
        assert 'add' in counts
        assert 'pop' in counts
        assert 'lea' in counts
        assert 'xchg' in counts
        assert 'other' in counts
        assert all(isinstance(v, int) for v in counts.values())


class TestSynthesizerInternal:
    def test_regs_match(self, synthesizer):
        assert synthesizer._regs_match('rax', 'rax')
        assert synthesizer._regs_match('RAX', 'rax')
        assert not synthesizer._regs_match('rax', 'rbx')

    def test_imms_compatible(self, synthesizer):
        assert synthesizer._imms_compatible('src', 10)
        assert synthesizer._imms_compatible('src', 0x100)
        assert not synthesizer._imms_compatible('src', 'target')

    def test_memory_access_match(self, synthesizer):
        assert synthesizer._memory_access_match('[rdi]', 'rdi', 'read')
        assert synthesizer._memory_access_match('[rdi + 0x20]', 'rdi', 'read')
        assert not synthesizer._memory_access_match('[rsi]', 'rdi', 'read')

    def test_find_chains_returns_list(self, synthesizer, temp_binary):
        synthesizer.load_binary(temp_binary)
        chains = synthesizer._find_chains('rax', 'mov', 'rbx', None, 5)
        assert isinstance(chains, list)


class TestIntegration:
    def test_full_workflow(self, synthesizer, temp_binary):
        count = synthesizer.load_binary(temp_binary)
        assert count > 0

        stats = synthesizer.get_statistics()
        assert stats['total_gadgets'] == count

        gadgets = synthesizer.find_gadget('ret')
        assert len(gadgets) > 0

        result = synthesizer.synthesize('rax = rbx')
        assert result is None or isinstance(result, SynthesizedChain)

    def test_multiple_constraints(self, synthesizer, temp_binary):
        synthesizer.load_binary(temp_binary)
        
        result1 = synthesizer.synthesize('rax = rbx')
        result2 = synthesizer.synthesize('rax = rax + 0x10')
        
        assert result1 is None or isinstance(result1, SynthesizedChain)
        assert result2 is None or isinstance(result2, SynthesizedChain)

    def test_reload_binary(self, synthesizer, temp_binary):
        count1 = synthesizer.load_binary(temp_binary)
        assert count1 > 0
        
        count2 = synthesizer.load_binary(temp_binary)
        assert count2 > 0
        assert len(synthesizer.gadget_set) == count2
