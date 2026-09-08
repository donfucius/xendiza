# Benchmark Fixtures

Real `.text` sections extracted from Windows system DLLs, used by
`xendiza_bench` to measure decode throughput on realistic instruction mixes
(containing SSE/AVX/AVX-512 bytes that xendiza does **not** cover, exercising
the `++off` resync slow path).

## Files

| fixture | source | `.text` bytes | `.text` RVA | source SHA256 | fixture SHA256 |
|---|---|---:|---:|---|---|
| `ntdll.text.bin` | `C:\Windows\System32\ntdll.dll` | 1,482,752 | `0x1000` | `b8f3a6aa...0087` | `aa28e5a5...9f3d` |
| `kernelbase.text.bin` | `C:\Windows\System32\kernelbase.dll` | 1,724,416 | `0x1000` | `8e8499fc...c07c` | `05b4a1ab...014a` |
| `kernel32.text.bin` | `C:\Windows\System32\kernel32.dll` | 544,768 | `0x1000` | `26410f49...c341` | `17943503...6031` |

**Total: 3,751,936 bytes (~3.58 MiB) of real x86-64 code.**

## Provenance

- **Extracted:** 2026-08-03
- **OS:** Windows-11-10.0.26200-SP0
- **Method:** `python bench/fixtures/extract_text.py` (zero-dependency minimal
  PE parser; DOS header → `e_lfanew` → PE signature → COFF header → optional
  header → section table → `.text` entry → raw bytes)
- **Full source SHA256** (not abbreviated) is reproducible by re-running the
  script; the table above shows the first/last 4 bytes for readability.

## Re-extracting

The fixtures are machine-specific (they reflect the exact patch level of the
source DLLs). To regenerate on your machine:

```sh
# Default: extracts ntdll, kernelbase, kernel32 from %SystemRoot%\System32
python bench/fixtures/extract_text.py

# Custom DLLs or paths
python bench/fixtures/extract_text.py C:\Windows\System32\ntdll.dll

# Override output directory / Windows root
python bench/fixtures/extract_text.py --outdir bench/fixtures --sysroot C:\Windows
```

The script overwrites existing `.text.bin` files in place and prints the
updated provenance table to stdout. After re-extraction, update the SHA256
values in this file (`python bench/fixtures/extract_text.py` prints them).

## Why these fixtures (not a synthetic seed)

The previous benchmark tiled a 79-byte hardcoded seed (only 1-byte legacy
opcodes that xendiza fully covers) to 8 MiB. This inflated xendiza's measured
advantage in three ways:

1. **Coverage bias** — the seed contained zero SSE/AVX/3-byte-escape bytes, so
   xendiza never hit its `UNIMPLEMENTED`/`UNDEFINED` slow path.
2. **Branch-prediction cheating** — a tiled 79-byte seed makes the `switch`
   dispatch in `Disasm` trivially predictable (~100% hit rate).
3. **Cache cheating** — the working set stays inside L1.

Real `.text` sections contain a representative mix of legacy + SSE + AVX
instructions, so xendiza will report a non-zero `errors` count (every AVX/SSE
byte sequence triggers resync). This is **expected and is exactly what the
benchmark should measure**: the cost of the resync path in real code, and the
net throughput advantage (if any) over Zydis, which decodes everything.
