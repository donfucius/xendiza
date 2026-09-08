#!/usr/bin/env python3
"""Extract the .text section from PE files (DLLs/EXEs) as raw byte fixtures.

Zero third-party dependencies: a minimal PE parser is hand-rolled here so the
script runs on any stock CPython 3.8+ on Windows.

Usage:
    python extract_text.py                       # default: ntdll, kernelbase, kernel32 from System32
    python extract_text.py <path.dll> [<path2.dll> ...]
    python extract_text.py --outdir <dir> <path.dll> ...
    python extract_text.py --sysroot C:\\Windows  # override Windows root (default: C:\\Windows)

Outputs <basename>.text.bin next to this script (or in --outdir) plus a
provenance line per file on stdout: name, source path, size, .text RVA,
SHA256 of the source file, SHA256 of the extracted bytes, OS version.
"""

from __future__ import annotations

import hashlib
import os
import struct
import sys
from pathlib import Path


# ── Minimal PE parser ──────────────────────────────────────────────────────

def read_pe_text_section(path: Path) -> tuple[bytes, int, int]:
    """Return (raw_text_bytes, text_rva, text_size_on_disk) for a PE file.

    Walks: DOS header -> e_lfanew -> PE signature -> COFF header ->
    optional header (PE32/PE32+) -> section table -> '.text' entry.
    """
    data = path.read_bytes()
    if len(data) < 0x40:
        raise ValueError(f"{path}: too small to be a PE file ({len(data)} bytes)")

    # DOS header: magic 'MZ' at 0, e_lfanew (offset to PE header) at 0x3C
    if data[0:2] != b"MZ":
        raise ValueError(f"{path}: missing MZ magic")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 24 > len(data):
        raise ValueError(f"{path}: e_lfanew {e_lfanew} out of bounds")

    # PE signature "PE\0\0" at e_lfanew
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        raise ValueError(f"{path}: missing PE signature at {e_lfanew:#x}")

    # COFF header (20 bytes) right after PE signature
    coff_off = e_lfanew + 4
    (machine, number_of_sections, _time_date, _ptr_sym, _num_sym,
     size_opt_hdr, characteristics) = struct.unpack_from("<HHIIIHH", data, coff_off)
    if machine not in (0x14c, 0x8664):  # i386, AMD64
        raise ValueError(f"{path}: unsupported machine {machine:#x}")

    # Optional header starts right after COFF header
    opt_off = coff_off + 20
    magic = struct.unpack_from("<H", data, opt_off)[0]
    if magic not in (0x10b, 0x20b):  # PE32, PE32+
        raise ValueError(f"{path}: unsupported optional header magic {magic:#x}")

    # Section table follows the optional header
    section_table_off = opt_off + size_opt_hdr
    # Each section header is 40 bytes; name is 8 bytes (null-padded, not necessarily terminated)
    text_bytes = b""
    text_rva = 0
    text_size_raw = 0
    for i in range(number_of_sections):
        off = section_table_off + i * 40
        name_field = data[off:off + 8]
        name = name_field.rstrip(b"\x00").decode("ascii", errors="replace")
        (_vsize, _vrva, raw_size, raw_ptr) = struct.unpack_from("<IIII", data, off + 8)
        # We want the first section named .text (some PEs have multiple; the
        # executable main code section is conventionally the first .text).
        if name == ".text":
            text_rva = _vrva
            text_size_raw = raw_size
            if raw_ptr + raw_size > len(data):
                raise ValueError(
                    f"{path}: .text raw [{raw_ptr:#x}..{raw_ptr + raw_size:#x}) "
                    f"exceeds file size {len(data)}"
                )
            text_bytes = data[raw_ptr:raw_ptr + raw_size]
            break

    if not text_bytes:
        # Fallback: pick the first executable section if no .text by name.
        for i in range(number_of_sections):
            off = section_table_off + i * 40
            name = data[off:off + 8].rstrip(b"\x00").decode("ascii", errors="replace")
            (_vsize, _vrva, raw_size, raw_ptr) = struct.unpack_from("<IIII", data, off + 8)
            chars = struct.unpack_from("<I", data, off + 36)[0]
            if chars & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
                text_rva = _vrva
                text_size_raw = raw_size
                text_bytes = data[raw_ptr:raw_ptr + raw_size]
                sys.stderr.write(
                    f"warning: {path}: no '.text' section, used executable section '{name}'\n"
                )
                break

    if not text_bytes:
        raise ValueError(f"{path}: no .text / executable section found")

    return text_bytes, text_rva, text_size_raw


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def windows_version() -> str:
    # Best-effort; not critical for correctness.
    try:
        import platform
        return platform.platform()
    except Exception:
        return "unknown"


# ── Main ───────────────────────────────────────────────────────────────────

DEFAULT_DLLS = ["ntdll.dll", "kernelbase.dll", "kernel32.dll"]


def main(argv: list[str]) -> int:
    args = list(argv[1:])
    outdir = Path(__file__).resolve().parent
    sysroot = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    targets: list[Path] = []

    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-h", "--help"):
            print(__doc__)
            return 0
        if a == "--outdir" and i + 1 < len(args):
            outdir = Path(args[i + 1]); i += 2; continue
        if a == "--sysroot" and i + 1 < len(args):
            sysroot = Path(args[i + 1]); i += 2; continue
        targets.append(Path(a)); i += 1

    if not targets:
        sys32 = sysroot / "System32"
        for name in DEFAULT_DLLS:
            targets.append(sys32 / name)

    outdir.mkdir(parents=True, exist_ok=True)
    osver = windows_version()

    print(f"# extract_text.py -- OS={osver} -- sysroot={sysroot}")
    print(f"# {'name':<20} {'source':<48} {'bytes':>10} {'text_rva':>10}  sha256(source)")
    print("# " + "-" * 120)

    rc = 0
    for src in targets:
        if not src.exists():
            sys.stderr.write(f"error: {src}: not found\n")
            rc = 1
            continue
        try:
            text_bytes, text_rva, _raw_size = read_pe_text_section(src)
        except ValueError as e:
            sys.stderr.write(f"error: {e}\n")
            rc = 1
            continue

        out_name = src.stem + ".text.bin"
        out_path = outdir / out_name
        out_path.write_bytes(text_bytes)

        src_sha = sha256_file(src)
        out_sha = sha256_bytes(text_bytes)
        print(f"  {src.stem:<20} {str(src):<48} {len(text_bytes):>10} "
              f"{text_rva:#10x}  {src_sha}")
        print(f"    -> {out_path.name}  sha256={out_sha}")

    return rc


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
