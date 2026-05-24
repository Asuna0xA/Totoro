# 💠 Totoro | Semantic ROP Chain Synthesizer

> *Binary exploitation, automated.*

Totoro is a high-performance, semantic ROP (Return-Oriented Programming) chain synthesizer. It bridges the gap between abstract exploit constraints and actionable gadget sequences. Write your constraints, and let Totoro navigate the binary's architecture to build your payload.

---

## 🛰️ Core Capabilities

- **Semantic Constraint Solving:** Translates high-level requirements into low-level gadget constraints.
- **Z3-Powered Synthesis:** Leverages the power of Z3 theorem proving for robust gadget discovery and chaining.
- **Architecture Agnostic:** Designed for flexibility across multiple ISA architectures.
- **High-Performance Search:** Optimized gadget discovery and chain construction.

## 🛠️ Running Routines

### Installation

```bash
pip install -e .
```

### Usage

```bash
python -m totoro --constraints <your_constraints.txt>
```

## 🧠 Philosophy

- **Automation is the ultimate force multiplier.**
- **Complexity is the attack surface.**
- **The machine doesn't lie; only the documentation does.**

---
_“The machine is waiting. Feed it your constraints.”_
