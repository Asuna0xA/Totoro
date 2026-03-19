import argparse
import sys
from . import Synthesizer, __version__

BANNER = r"""
    ██╗  ██╗ █████╗ ██╗     ██╗    ██╗    ██╗ ██████╗ ███╗   ██╗
    ██║  ██║██╔══██╗██║     ██║    ██║    ██║██╔═══██╗████╗  ██║
    ███████║███████║██║     ██║    ██║ █╗ ██║██║   ██║██╔██╗ ██║
    ██╔══██║██╔══██║██║     ██║    ██║███╗██║██║   ██║██║╚██╗██║
    ██║  ██║██║  ██║███████╗██║    ╚███╔███╔╝╚██████╔╝██║ ╚████║
    ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝     ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═══╝
                                                                  
    Semantic ROP Chain Synthesizer v{version}
""".format(version=__version__)

def main():
    parser = argparse.ArgumentParser(
        description="Totoro - Semantic ROP Chain Synthesizer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m totoro /bin/ls "rax = rbx"
  python -m totoro /bin/ls "rax = read(rdi + 0x20)"
  python -m totoro /bin/ls "rax = read(rdi + 0x20) + 0x100"
  python -m totoro /bin/ls --search "pop rax"
  python -m totoro /bin/ls --stats
        """
    )
    
    parser.add_argument('binary', nargs='?', help='Target binary to analyze')
    parser.add_argument('constraint', nargs='?', help='Constraint expression (e.g., "rax = rbx")')
    parser.add_argument('--search', '-s', metavar='PATTERN', help='Search for gadgets matching pattern')
    parser.add_argument('--stats', action='store_true', help='Show gadget statistics')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
    
    args = parser.parse_args()
    
    print(BANNER)
    
    if args.search:
        if not args.binary:
            print("Error: --search requires a binary path")
            sys.exit(1)
        synth = Synthesizer()
        count = synth.load_binary(args.binary)
        print(f"Loaded {count} gadgets from {args.binary}\n")
        results = synth.find_gadget(args.search)
        print(f"Found {len(results)} gadgets matching '{args.search}':\n")
        for g in results:
            print(f"  0x{g.address:x}: {g.instruction}")
        return
        
    if args.stats:
        if not args.binary:
            print("Error: --stats requires a binary path")
            sys.exit(1)
        synth = Synthesizer()
        count = synth.load_binary(args.binary)
        print(f"Loaded {count} gadgets from {args.binary}\n")
        stats = synth.get_statistics()
        print("Gadget Statistics:")
        print(f"  Total gadgets: {stats['total_gadgets']}")
        print("  By type:")
        for typ, cnt in stats['by_type'].items():
            print(f"    {typ}: {cnt}")
        return
        
    if not args.binary or not args.constraint:
        parser.print_help()
        sys.exit(1)
        
    synth = Synthesizer()
    print(f"Loading binary: {args.binary}")
    count = synth.load_binary(args.binary)
    print(f"Loaded {count} gadgets\n")
    
    print(f"Synthesizing constraint: {args.constraint}\n")
    chain = synth.synthesize(args.constraint)
    
    if chain:
        print(chain)
    else:
        print("No matching ROP chain found.")
        print("\nTip: Try simpler constraints like 'rax = rbx' or 'rax = rax + 0x10'")

if __name__ == '__main__':
    main()
