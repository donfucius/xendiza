#ifndef XENDIZA_C_H
#define XENDIZA_C_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct xendiza_decoded_instruction_t {
    uint8_t length;
    uint16_t opcode;
    uint8_t operand_count;
    uint16_t operands[4];
} xendiza_decoded_instruction_t;

xendiza_decoded_instruction_t xendiza_disasm64(const uint8_t* buffer, size_t size);
xendiza_decoded_instruction_t xendiza_disasm32(const uint8_t* buffer, size_t size);

#ifdef __cplusplus
}
#endif

#endif // XENDIZA_C_H
