#!/usr/bin/env python3
"""Compare xendiza harness output against converted capstone/zydis vectors."""
import json
import os
import re
import subprocess
import sys
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))  # repo root (test/diff/ -> test/ -> root)
OUT = os.path.join(HERE, "out")
HARNESS = os.path.join(OUT, "harness.exe")

R8 = set("al cl dl bl ah ch dh bh spl bpl sil dil".split())
R16 = set("ax cx dx bx sp bp si di".split())
R32 = set("eax ecx edx ebx esp ebp esi edi".split())
R64 = set("rax rcx rdx rbx rsp rbp rsi rdi".split())
SREGS = set("es cs ss ds fs gs".split())
BRANCH_MNEMONICS = set(
    "JMP CALL JO JNO JB JAE JZ JNZ JBE JA JS JNS JP JNP JL JGE JLE JG JRCXZ "
    "LOOP LOOPE LOOPNE".split())

MN_CANON = {"IRET": "IRET", "IRETD": "IRET", "IRETQ": "IRET"}
for _n in ("STOSB", "STOSW", "STOSD", "STOSQ"):
    MN_CANON[_n] = "STOS"
for _n in ("LODSB", "LODSW", "LODSD", "LODSQ"):
    MN_CANON[_n] = "LODS"
for _n in ("SCASB", "SCASW", "SCASD", "SCASQ"):
    MN_CANON[_n] = "SCAS"
for _n in ("CMPSB", "CMPSW", "CMPSD", "CMPSQ"):
    MN_CANON[_n] = "CMPS"
for _n in ("MOVSB", "MOVSW", "MOVSD", "MOVSQ"):
    MN_CANON[_n] = "MOVS"
for _n in ("INSB", "INSW", "INSD"):
    MN_CANON[_n] = "INS"
for _n in ("OUTSB", "OUTSW", "OUTSD"):
    MN_CANON[_n] = "OUTS"
# xendiza width-specific string names vs capstone/zydis generic names
MN_CANON.update({"STOS": "STOS", "LODS": "LODS", "SCAS": "SCAS", "CMPS": "CMPS",
                 "MOVS": "MOVS", "INS": "INS", "OUTS": "OUTS"})

def norm(op):
    if op in R8 or re.fullmatch(r"r\d+b", op):
        return ("reg", "8")
    if op in R16 or re.fullmatch(r"r\dw", op):
        return ("reg", "16")
    if op in R32 or re.fullmatch(r"r\dd", op):
        return ("reg", "32")
    if op in R64 or re.fullmatch(r"r\d+_reg", op):
        return ("reg", "64")
    if op in SREGS or op == "sreg":
        return ("sreg",)
    m = re.fullmatch(r"(?:es|cs|ss|ds|fs|gs)_m(?:offs)?(\d+)", op)
    if m:  # composite segment-prefixed memory -> plain memory class
        return ("mem", m.group(1))
    m = re.fullmatch(r"moffs(\d+)", op)
    if m:
        return ("mem", m.group(1))
    if op == "m32fp":
        return ("mem", "32")
    if op == "m64fp":
        return ("mem", "64")
    if op == "m80fp":
        return ("mem", "80")
    if op == "m80":
        return ("mem", "80")
    if op == "m16_32":
        return ("farp", "32")
    if op == "ptr16_32":
        return ("farp", "32")
    if op == "ptr16_16":
        return ("farp", "16")
    m = re.fullmatch(r"rm(\d+)", op)
    if m:  # r/m wildcard: matches both register and memory forms
        return ("wild", m.group(1))
    m = re.fullmatch(r"stack_m(\d+)", op)
    if m:
        return ("mem", m.group(1))
    m = re.fullmatch(r"m(\d+)", op)
    if m:
        return ("mem", m.group(1))
    m = re.fullmatch(r"r(\d+)", op)
    if m:
        return ("reg", m.group(1))
    m = re.fullmatch(r"imm(\d+)", op)
    if m:
        return ("imm", m.group(1))
    m = re.fullmatch(r"rel(\d+)", op)
    if m:
        return ("rel", m.group(1))
    return ("exact", op)

def ops_match(exp, act, mnemonic):
    if len(exp) != len(act):
        return False
    for e, a in zip(exp, act):
        ne, na = norm(e), norm(a)
        if ne == na:
            continue
        if ne[0] == "wild" and na[0] in ("reg", "mem") and ne[1] == na[1]:
            continue
        if na[0] == "wild" and ne[0] in ("reg", "mem") and na[1] == ne[1]:
            continue
        # capstone reports branch targets as IMM (Intel SDM view);
        # xendiza reports them as rel8/rel16/rel32.
        if (mnemonic in BRANCH_MNEMONICS
                and {ne[0], na[0]} == {"imm", "rel"}):
            continue
        # capstone reports sign-extended immediates at their effective size
        # (0x6B/0x83 imm8 -> imm32, 6A push imm8 -> imm64 in 64-bit mode);
        # xendiza reports the encoded width.
        if ne[0] == na[0] == "imm" and {ne[1], na[1]} in ({"8", "32"}, {"8", "64"}):
            continue
        return False
    return True

STRING_MNEMONICS = set("MOVS CMPS STOS LODS SCAS INS OUTS".split())

def ops_match_lenient(exp, act, mnemonic):
    canon = MN_CANON.get(mnemonic, mnemonic)
    if not act and canon in STRING_MNEMONICS:
        # xendiza reports string instructions without explicit operands
        return True
    if ops_match(exp, act, mnemonic):
        return True
    # some capstone cases list operands in AT&T order even under Intel syntax;
    # retry against all orderings (operand count <= 4)
    import itertools
    for perm in itertools.permutations(range(len(act))):
        if all(_class_eq(e, act[j], canon) for e, j in zip(exp, perm)):
            return True
    return False

def _class_eq(e, a, mnemonic):
    ne, na = norm(e), norm(a)
    if ne == na:
        return True
    if ne[0] == "wild" and na[0] in ("reg", "mem") and ne[1] == na[1]:
        return True
    if na[0] == "wild" and ne[0] in ("reg", "mem") and na[1] == ne[1]:
        return True
    if mnemonic in BRANCH_MNEMONICS and {ne[0], na[0]} == {"imm", "rel"}:
        return True
    if ne[0] == na[0] == "imm" and {ne[1], na[1]} in ({"8", "32"}, {"8", "64"}):
        return True
    return False

def main():
    streams = [json.loads(l) for l in open(os.path.join(OUT, "streams.jsonl"))]
    tsv = os.path.join(OUT, "streams.tsv")
    out = subprocess.run([HARNESS], stdin=open(tsv, "rb"),
                         capture_output=True, text=True, check=True).stdout

    actual = {}  # (srcid, idx) -> (length, mnemonic, ops)
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) < 5:
            continue
        srcid, idx, length, mn, ops = parts[0], int(parts[1]), parts[2], parts[3], parts[4]
        actual[(srcid, idx)] = (int(length), mn, [o for o in ops.split(",") if o])

    stats = Counter()
    by_src = defaultdict(Counter)
    mismatches = []
    for s in streams:
        srcid = f"{s['src']}:{s['id']}"
        for i, exp in enumerate(s["insns"]):
            a = actual.get((srcid, i))
            cat = by_src[s["src"]]
            if exp["mnemonic"] is None:
                stats["skipped-unmapped-mnemonic"] += 1
                cat["skipped-unmapped"] += 1
                continue
            if a is None:
                stats["missing-actual"] += 1
                cat["missing-actual"] += 1
                continue
            length, mn, ops = a
            key = f"{srcid}[{i}] {s['mode']}bit {s['bytes']}"
            if length >= 0xE0:
                stats["xendiza-error"] += 1
                cat["xendiza-error"] += 1
                mismatches.append((key, exp, f"ERROR length={length:#x}"))
                continue
            if MN_CANON.get(mn, mn) != MN_CANON.get(exp["mnemonic"], exp["mnemonic"]):
                stats["mnemonic-mismatch"] += 1
                cat["mnemonic-mismatch"] += 1
                mismatches.append((key, exp, f"mnemonic: got {mn} ops={ops}"))
                continue
            if exp["ops"] is not None and not ops_match_lenient(exp["ops"], ops, mn):
                stats["operand-mismatch"] += 1
                cat["operand-mismatch"] += 1
                mismatches.append((key, exp, f"ops: got {ops}"))
                continue
            if exp.get("size") and length != exp["size"]:
                stats["length-mismatch"] += 1
                cat["length-mismatch"] += 1
                mismatches.append((key, exp, f"length: got {length}"))
                continue
            stats["match"] += 1
            cat["match"] += 1

    checked = stats["match"] + stats["mnemonic-mismatch"] + stats["operand-mismatch"] + \
        stats["length-mismatch"] + stats["xendiza-error"]
    print("=== differential check: xendiza vs capstone/zydis vectors ===")
    print(f"vectors (streams): {len(streams)}")
    for k, v in sorted(stats.items()):
        print(f"  {k:32s} {v}")
    if checked:
        agree = stats["match"] / checked * 100
        print(f"agreement (of comparable): {agree:.1f}%")
    print("\n--- by source ---")
    for src, c in sorted(by_src.items()):
        total = sum(c.values())
        print(f"  {src:10s} {dict(c)}")
    print("\n--- first 40 mismatches ---")
    for key, exp, got in mismatches[:40]:
        exp_s = {k: v for k, v in exp.items() if v is not None}
        print(f"  {key}\n    expected: {exp_s}\n    actual  : {got}")

    with open(os.path.join(OUT, "report.json"), "w") as f:
        json.dump({"stats": dict(stats),
                   "by_source": {k: dict(v) for k, v in by_src.items()},
                   "mismatches": [{"key": k, "expected": e, "actual": g}
                                  for k, e, g in mismatches]},
                  f, indent=1)

if __name__ == "__main__":
    main()
