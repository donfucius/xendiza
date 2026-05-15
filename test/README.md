# xendiza Test Suite

This directory contains comprehensive unit tests for the xendiza x86-64 disassembler library.

## Test Organization

### `test_basic_instructions.cpp`
Tests for fundamental 1-byte opcode instructions (without opcode extensions).

**Coverage:**
- **Arithmetic/Logic Operations**: ADD, OR, ADC, SBB, AND, SUB, XOR, CMP
  - All ModR/M addressing modes: mod=00 (indirect), mod=01 (indirect+disp8), mod=10 (indirect+disp32), mod=11 (register)
  - With and without SIB (Scale-Index-Base) bytes
  - Immediate operand variants (imm8, imm32)
  
- **Data Movement**: MOV (all variants), XCHG, PUSH/POP
  - Memory to register, register to memory, register to register
  - Direct memory offsets (moffs)
  
- **Control Flow**: 
  - Conditional jumps (Jcc: JO, JNO, JB, JAE, JE, JNE, JBE, JA, JS, JNS, JP, JNP, JL, JGE, JLE, JG)
  - CALL, RET, RETF
  - LOOP, LOOPE, LOOPNE, JRCXZ
  
- **String Operations**: MOVSB, MOVSD, CMPSB, CMPSD, STOSB, STOSD, LODSB, LODSD, SCASB, SCASD

- **I/O Operations**: IN, OUT (with immediate and DX port)

- **System & Flags**: INT, HLT, CLC, STC, CLI, STI, CLD, STD

- **Miscellaneous**: NOP, TEST, XLAT, ENTER, LEAVE

Test count evolves with coverage expansion; use `ctest -N` in your build directory for the current number.

---

### `test_opcode_extensions.cpp`
Tests for instructions that use opcode extensions via the ModR/M.reg field, including prefix handling.

**Coverage:**

#### 1. **Prefix Handling** (REX.W, 0x66)
- REX.W prefix (0x48): Forces 64-bit operands
- 0x66 prefix: Forces 16-bit operands
- Verifies 8-bit operations are unaffected by prefixes

#### 2. **Group 1: Arithmetic/Logic with Immediate** (0x80-0x83)
- **Opcodes**: 0x80 (r/m8, imm8), 0x81 (r/m32, imm32), 0x83 (r/m32, imm8)
- **Instructions**: ADD, OR, ADC, SBB, AND, SUB, XOR, CMP
- **Prefix variants**: Default (32-bit), REX.W (64-bit), 0x66 (16-bit)

#### 3. **Group 2: Shift/Rotate with Immediate** (0xC0-0xC1)
- **Instructions**: ROL, ROR, RCL, RCR, SHL, SHR, SAL, SAR
- **Forms**: r/m with imm8
- **Prefix variants**: 8-bit, 32-bit, 64-bit, 16-bit

#### 4. **Group 3: Shift/Rotate by 1 or CL** (0xD0-0xD3)
- **Instructions**: ROL, ROR, RCL, RCR, SHL, SHR, SAL, SAR
- **Forms**: 
  - 0xD0/0xD1: shift by 1
  - 0xD2/0xD3: shift by CL register
- **Prefix variants**: All operand sizes

#### 5. **Group 4: MOV Immediate** (0xC6-0xC7)
- **Instructions**: MOV r/m, immediate
- **Prefix handling**: Adjusts immediate size (32→16 bits with 0x66)

#### 6. **Group 5: Unary Operations** (0xF6-0xF7)
- **Instructions**: TEST, NOT, NEG, MUL, IMUL, DIV, IDIV
- **Prefix variants**: 8-bit, 16-bit, 32-bit, 64-bit

#### 7. **Group 6: INC/DEC/CALL/JMP/PUSH** (0xFE-0xFF)
- **Instructions**: INC, DEC, CALL, JMP, PUSH
- **Prefix variants**: All operand sizes

#### 8. **Special: IMUL Three-Operand Form** (0x69-0x6B)
- **Forms**:
  - 0x69: IMUL r, r/m, imm32
  - 0x6B: IMUL r, r/m, imm8
- **Prefix variants**: 16-bit, 32-bit, 64-bit

#### 9. **Edge Cases**
- 8-bit operations unaffected by REX.W or 0x66
- Memory operands with prefixes
- SIB byte with prefixes
- Immediate size adjustments

Test count evolves with coverage expansion; use `ctest -N` in your build directory for the current number.

---

### `test_public_api.cpp`
Tests the public API surface exposed from `xendiza.hpp` and the C ABI shim in `xendiza_c.h`.

**Coverage:**
- `xendiza::Disasm<64>(gsl::span<uint8_t>)`
- `xendiza::Disasm<64>(gsl::span<std::byte>)`
- C ABI parity via `xendiza_disasm64(const uint8_t*, size_t)`

Test count evolves with coverage expansion; use `ctest -N` in your build directory for the current number.

---

### `test_2byte_opcodes.cpp`
Tests the implemented `0x0F` two-byte opcode subset.

**Coverage:**
- `Jcc rel32`, `CMOVcc`, `IMUL r,r/m`, `BSF`, `BSR`
- `MOVZX`/`MOVSX` (`0F B6/B7/BE/BF`)
- `CMPXCHG` (`0F B0/B1`), `XADD` (`0F C0/C1`)
- `BT/BTS/BTR/BTC` (`0F A3/AB/B3/BB`)
- `BT/BTS/BTR/BTC` immediate group (`0F BA /4-/7`, `imm8`)
- `SETcc` (`0F 90-9F`)
- `BSWAP` (`0F C8-CF`)
- Multibyte `NOP` (`0F 1F /0`)
- Direct system/control opcodes (`0F 05/06/07/08/09/0B/31/A0/A1/A2/A8/A9`, `0F AE` fences/flush)
- `SHLD`/`SHRD` (`0F A4/A5/AC/AD`) with `imm8` and `CL` forms
- Prefix/length behavior (`REX.W`, `0x66` where applicable), plus error paths

Test count evolves with coverage expansion; use `ctest -N` in your build directory for the current number.

---

### `test_no_operands.cpp`
Dedicated tests for instructions with no explicit operands.

**Coverage:**
- 1-byte no-operand instructions such as `NOP`, `RET`, `HLT`, `CLC/STC`, `CLI/STI`, `CLD/STD`, `PUSHFQ/POPFQ`, `CDQ`
- 2-byte no-operand instruction check (`RDTSC`)
- Verifies `operand_count == 0` for these forms

Test count evolves with coverage expansion; use `ctest -N` in your build directory for the current number.

---

### `test_x87_opcodes.cpp`
Tests the implemented x87 core one-byte opcode family (`D8`-`DF`) with abstract operand forms.

**Coverage:**
- Memory and register-stack forms across the x87 decode path (`st0`/`sti`, `m32fp`/`m64fp`/`m80fp`)
- Environment/control instructions (`FLDENV`, `FNSTENV`, `FSAVE`, `FRSTOR`)
- BCD forms (`FBLD`, `FBSTP`)
- Distinction checks between `FWAIT` (`0x9B`) and `FN*` forms
- Reserved/invalid encodings and insufficient-buffer behavior

Test count evolves with coverage expansion; use `ctest -N` in your build directory for the current number.

---

## Test Statistics

- Current totals and pass/fail status are build-dependent snapshots; run `ctest --output-on-failure` for the latest result.
- Core coverage focus remains: 1-byte map + selected `0x0F` subset + P2 minimal SIMD path.
- Prefix combinations covered include default/no-prefix, `REX.W`, `REX.B`, and `0x66` (where applicable).
- ModR/M addressing modes are exercised across `00`, `01`, `10`, `11` in relevant suites.

---

## Operand Contract (Current Scope)

- Tests follow the same global operand contract as `README.md`: decode assertions stop at the operand-form layer for all implemented instruction families.
- Tests assert abstract operand classes (`r*`/`m*`) instead of concrete register numbers.
- `REX.W` and `0x66` are validated for width/length effects.
- `REX.B/R/X` presence must not change assertions into concrete extended-register identities.

---

## Running Tests

### Run all tests:
```bash
ctest --output-on-failure
```

### Run specific test suite:
```bash
ctest -R "DisasmTest"        # Basic instructions
ctest -R "OpcodeExtTest"     # Opcode extensions
ctest -R "PublicApiTest"     # Public C++/C API tests
ctest -R "TwoByteOpcodeTest" # 0x0F two-byte subset
ctest -R "NoOperandTest"     # No-operand instruction semantics
ctest -R "X87OpcodeTest"     # x87 D8-DF core matrix
```

### Run with verbose output:
```bash
ctest --verbose
```

### Run tests in parallel:
```bash
ctest -j8
```

---

## Test Naming Convention

### Basic Instructions (`DisasmTest`)
Format: `{MNEMONIC}_{OPCODE}_{VARIANT}`

Examples:
- `ADD_0x00_modrm_00_000` - ADD with mod=00, r/m=000
- `PUSH_all_regs` - PUSH for all register encodings
- `Jcc_all_conditions` - All conditional jumps

### Opcode Extensions (`OpcodeExtTest`)
Format: `{MNEMONIC}_{OPCODE}_{PREFIX}_{OPERANDS}`

Examples:
- `ADD_0x81_REX_W_r64_imm32` - ADD with REX.W prefix
- `ROL_0xC1_Prefix66_r16_imm8` - ROL with 0x66 prefix
- `ADD_0x80_r8_imm8_with_REXW_no_effect` - Edge case test

---

## Helper Macros

```cpp
#define MKINSTR(opc, opr) \
    mkinst(static_cast<uint32_t>(detail::OpcodeId::opc), \
           static_cast<uint32_t>(detail::OperandType::opr))
```

Creates an instruction identifier from opcode and operand type for testing.

---

## Coverage Analysis

### Implemented & Tested
- ✅ All basic arithmetic/logic operations
- ✅ All MOV variants
- ✅ Stack operations (PUSH/POP)
- ✅ Conditional jumps (Jcc)
- ✅ String operations
- ✅ I/O instructions
- ✅ All opcode extensions (Groups 1-6)
- ✅ IMUL three-operand forms
- ✅ System/flag instructions
- ✅ No-operand instruction semantics (`operand_count == 0`)
- ✅ REX.W and 0x66 prefix handling
- ✅ 0x0F two-byte subset (`Jcc rel32`, `CMOVcc`, `IMUL r,r/m`, `BSF`, `BSR`, `CMPXCHG`, `XADD`, `BT/BTS/BTR/BTC` including `0F BA /4-/7 imm8`, `SETcc`, `BSWAP`, `NOP 0F 1F /0`, direct system/control opcodes including `LFENCE`/`MFENCE`/`SFENCE`/`CLFLUSH`, `SHLD`, `SHRD`)
- ✅ P2.4 minimal SIMD path (`MOVUPS` `0F 10/11`, `MOVAPS` `0F 28/29`, `UCOMISS/COMISS` `0F 2E/2F`, and `66`-prefixed `UCOMISD/COMISD`)
- ✅ x87 core D8-DF path with abstract operand forms (including env/control forms `FLDENV`/`FNSTENV`/`FSAVE`/`FRSTOR`, BCD forms `FBLD`/`FBSTP`, and `FWAIT` vs `FN*` distinction checks)

### Not Yet Tested
- ❌ Remaining 2-byte opcodes (0x0F prefix)
- ❌ Broader x87 coverage beyond current D8-DF core matrix
- ❌ Broader SSE/AVX and VEX/EVEX instruction families beyond the P2.4 minimal SIMD subset
- ❌ REX.R and REX.X combinations
- ❌ Address size prefix (0x67)
- ❌ Segment override prefixes
- ❌ LOCK prefix

---

## Future Enhancements

1. **Expand 2-byte opcode tests** (0x0F prefix)
   - Additional integer instructions beyond current subset
   - Incremental SSE/SSE2 coverage beyond current minimal SIMD set

2. **Add REX prefix combination tests**
   - Additional REX.R and REX.X variations
   - Concrete register extensions (`R8-R15`) are currently out of scope

3. **Add address size prefix tests** (0x67)

4. **Add segment override tests** (CS, DS, ES, FS, GS, SS)

5. **Add LOCK prefix tests** (for atomic operations)

6. **Expand benchmark corpus coverage**

---

## Benchmarking

The repo includes a benchmark executable at `bench/bench_disasm.cpp`.

### Build benchmark (xendiza only)
```bash
cmake -S . -B build
cmake --build build --target xendiza_bench
```

### Build benchmark with Zydis + Capstone (vcpkg)
```bash
cmake -S . -B build-vcpkg-rel \
  -DCMAKE_TOOLCHAIN_FILE=C:/devdrv/scoop/apps/vcpkg/current/scripts/buildsystems/vcpkg.cmake \
  -DVCPKG_TARGET_TRIPLET=x64-windows \
  -DXENDIZA_BENCH_WITH_CAPSTONE=ON \
  -DXENDIZA_BENCH_WITH_ZYDIS=ON \
  -DCMAKE_BUILD_TYPE=Release

cmake --build build-vcpkg-rel --config Release --target xendiza_bench
```

### Run benchmark
```bash
./build-vcpkg-rel/Release/xendiza_bench.exe --mb 8 --iters 30
```

### Latest reference result (`--mb 8 --iters 30`, Release)

| Decoder | Throughput | Decode Rate |
|--------|------------|-------------|
| xendiza | 73.71 MiB/s | 26.42 Minsn/s |
| zydis | 50.98 MiB/s | 18.27 Minsn/s |
| capstone | 12.92 MiB/s | 4.63 Minsn/s |

All three decoders completed with `decoded=86009850`, `errors=0` on this corpus.

Notes:
- Capstone must be installed with x86 support (`capstone[x86]`) for x64 decoding.
- Benchmark numbers are machine- and compiler-dependent; compare with identical build type and workload.

---

## Contributing

When adding new tests:
1. Follow the existing naming conventions
2. Group related tests together with clear section comments
3. Test all ModR/M modes where applicable
4. Include prefix variants (REX.W, 0x66) for sized operations
5. Add edge cases and boundary conditions
6. Update this README with new coverage

---

## Build Requirements

- **C++ Standard**: C++20
- **Build System**: CMake 3.20+
- **Test Framework**: Google Test (GTest)
- **Compiler**: MSVC 14.44+ / GCC 10+ / Clang 12+

---

Last Updated: 2026-05
