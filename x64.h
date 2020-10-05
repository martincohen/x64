#pragma once

// ---
// Author:  Martin 'Halt' Cohen, @martin_cohen
// License: MIT (see LICENSE)
// ---

#include <stdbool.h>
#include <stdint.h>

// NOTE: To use these, you'll have to include appropriate headers yourself.

#ifndef X64_ERROR
    #define X64_ERROR(Message) { printf(Message); abort(); }
#endif

#ifndef X64_ASSERT
    #define X64_ASSERT assert
#endif

#ifndef X64_ASSERT_DEBUG
    #define X64_ASSERT_DEBUG assert
#endif

#define X64_TODO X64_ERROR("todo")

typedef enum X64Reg {
    X64_None = 0,

    X64_RAX, // 000
    X64_RCX, // 001
    X64_RDX, // 010
    X64_RBX, // 011
    X64_RSP, // 100
    X64_RBP, // 101
    X64_RSI, // 110
    X64_RDI, // 111

    X64_R8,  // 1.000
    X64_R9,  // 1.001
    X64_R10, // 1.010
    X64_R11, // 1.011
    X64_R12, // 1.100
    X64_R13, // 1.101
    X64_R14, // 1.110
    X64_R15, // 1.111

    X64Reg_LAST__,

    // Special-case register, used for RIP-based addressing mode with Mod R/M.
    X64_RIP,
} X64Reg;

#define x64reg_check(Reg) \
    X64_ASSERT_DEBUG((Reg) > X64_None && (Reg) < X64Reg_LAST__)

#define x64reg_is_int_ext(Reg) \
    ((Reg) >= X64_R8 && (Reg) <= X64_R15)
//
//
//

typedef enum X64Size {
    X64_SDefault,
    X64_S8,
    X64_S16,
    X64_S32,
    X64_S64,
} X64Size;

typedef enum X64Scale {
    X64_X1 = 0b00,
    X64_X2 = 0b01,
    X64_X4 = 0b10,
    X64_X8 = 0b11,
} X64Scale;

typedef enum X64OperandKind {
    X64O_Reg,
    X64O_Mem,
    X64O_Imm
} X64OperandKind;

typedef struct X64Operand {
    X64OperandKind kind;
    union {
        X64Reg reg;
        struct {
            X64Reg base;
            X64Reg index;
            X64Scale scale;
            // TODO: Is this supposed to be signed int?
            int32_t displacement;
        } mem;
        uint64_t imm;
    };
} X64Operand;

#define x64o_pair(A, B) ((A << 4) | B)

#define x64r(Reg) \
    (X64Operand) { .kind = X64O_Reg, .reg = Reg }

#define x64m(Base, Index, Scale, Displacement) \
    (X64Operand) { \
        .kind = X64O_Mem, \
        .mem.base = Base, \
        .mem.index = Index, \
        .mem.scale = Scale, \
        .mem.displacement = Displacement \
    }

#define x64i(Immediate) \
    (X64Operand) { .kind = X64O_Imm, .imm = (Immediate) }

#define x64o_swap(A, B) { \
        X64Operand t = A; \
        A = B; \
        B = t; \
    }

//
//
//

typedef enum X64ModRMMode {
    X64ModRM_Indirect       = 0b00,
    X64ModRM_IndirectDisp8  = 0b01,
    X64ModRM_IndirectDisp32 = 0b10,
    X64ModRM_Direct         = 0b11,
} X64ModRMMode;

//
//
//

// Whenever we have `rm` we encode other register in modrm.reg.
// Otherwise (reg/imm) we encode register in opcode.

// Using int16_t to be able to denote -1 as "not available" in
// case the opset doesn't support it. This is because `0` is
// used with ADD r/m8,r8.
typedef struct X64OpBinary
{
    // Register in modrm.reg
    // Opcode must support 16, 32 and 64 operand sizes.
    int16_t reg_rm;
    // Register in modrm.reg
    // Opcode must support 16, 32 and 64 operand sizes.
    int16_t rm_reg;

    // Register in modrm.reg.
    int16_t rm8_reg8;
    // Register in modrm.reg.
    // In case of (reg8, reg8) GCC seems to refer rm8_reg8,
    // while ML64 preferes reg8_rm8.
    // TODO: Check if there's any difference.
    int16_t reg8_rm8;

    // rmX_immX:
    //  - In case when used for writing to a register:
    //  - modrm.mode = 11
    //  - modrm.reg = 0
    //  - modrm.rm = destination register

    // rmX_immX
    // Opcode must support 16, 32 and 64 operand sizes.
    int16_t rm_imm8;
    // Extends rm_imm8 opcode with modrm.reg field.
    // Opcode must support 16, 32 and 64 operand sizes.
    int16_t rm_imm8_op;

    // rmX_immX
    // Opcode must support 16, 32 and 64 operand sizes.
    int16_t rm_imm32;
    // Extends rm_imm32 opcode with modrm.reg field.
    int16_t rm_imm32_op;

    // rmX_immX
    // So far all opcodes have this note: In 64-bit no AH, BH, CH, DH.
    int16_t rm8_imm8;
    // Extends rm8_imm8 opcode with modrm.reg field.
    int16_t rm8_imm8_op;

    // Regsiter in opcode.
    int16_t reg8_imm8;
    // Register in opcode.
    // In 64-bit the imm32 is sign-extended to 64-bit.
    // So far all opcodes support 16, 32 and sign-extended 64.
    int16_t reg32_imm32;
    // Register in opcode.
    // So far reg32_imm32 with reg.
    // So far only mov has this variant.
    int16_t reg64_imm64;
} X64OpBinary;

const X64OpBinary X64Op_Mov =
{
    .reg_rm         = 0x8B,
    .rm_reg         = 0x89,
    .rm8_reg8       = 0x88,
    .reg8_rm8       = 0x8A,
    .rm_imm8        = -1,
    .rm_imm32       = 0xC7, .rm_imm32_op = 0,
    .rm8_imm8       = 0xC6, .rm8_imm8_op = 0,
    .reg8_imm8      = 0xB0,
    .reg32_imm32    = 0xB8,
    .reg64_imm64    = 0xB8,
};

const X64OpBinary X64Op_Sub =
{
    .reg_rm         = 0x2B,
    .rm_reg         = 0x29,
    .rm8_reg8       = 0x28,
    .reg8_rm8       = 0x2A,
    .rm_imm8        = 0x83, .rm_imm8_op = 5,
    .rm_imm32       = 0x81, .rm_imm32_op = 5,
    .rm8_imm8       = 0x80, .rm8_imm8_op = 5,
    .reg8_imm8      = -1, // Not available.
    .reg32_imm32    = -1, // Not available.
    .reg64_imm64    = -1, // Not available.
    // TODO: reg8_imm8   only for AL
    // TODO: reg32_imm32 only for AX, EAX, RAX.
};

const X64OpBinary X64Op_Add =
{
    .reg_rm         = 0x03,
    .rm_reg         = 0x01,
    .rm8_reg8       = 0x00,
    .reg8_rm8       = 0x02,
    .rm_imm8        = 0x83, .rm_imm8_op  = 0,
    .rm_imm32       = 0x81, .rm_imm32_op = 0,
    .rm8_imm8       = 0x80, .rm8_imm8_op = 0,
    .reg8_imm8      = -1,
    .reg32_imm32    = -1,
    .reg64_imm64    = -1,
    // TODO: reg8_imm8   only for AL
    // TODO: reg32_imm32 only for AX, EAX, RAX.
};

const X64OpBinary X64Op_And =
{
    .reg_rm         = 0x23,
    .rm_reg         = 0x21,
    .rm8_reg8       = 0x20,
    .reg8_rm8       = 0x22,
    .rm_imm8        = 0x83, .rm_imm8_op  = 4,
    .rm_imm32       = 0x81, .rm_imm32_op = 4,
    .rm8_imm8       = 0x80, .rm8_imm8_op = 4,
    .reg8_imm8      = -1,
    .reg32_imm32    = -1,
    .reg64_imm64    = -1,
};

const X64OpBinary X64Op_Or =
{
    .reg_rm         = 0x0B,
    .rm_reg         = 0x09,
    .rm8_reg8       = 0x08,
    .reg8_rm8       = 0x0A,
    .rm_imm8        = 0x83, .rm_imm8_op  = 1,
    .rm_imm32       = 0x81, .rm_imm32_op = 1,
    .rm8_imm8       = 0x80, .rm8_imm8_op = 1,
    .reg8_imm8      = -1,
    .reg32_imm32    = -1,
    .reg64_imm64    = -1,
};

const X64OpBinary X64Op_Xor =
{
    .reg_rm         = 0x33,
    .rm_reg         = 0x31,
    .rm8_reg8       = 0x30,
    .reg8_rm8       = 0x32,
    .rm_imm8        = 0x83, .rm_imm8_op  = 6,
    .rm_imm32       = 0x81, .rm_imm32_op = 6,
    .rm8_imm8       = 0x80, .rm8_imm8_op = 6,
    .reg8_imm8      = -1,
    .reg32_imm32    = -1,
    .reg64_imm64    = -1,
};

typedef struct X64OpUnary {
    uint8_t rm;
    // Number to use on 'modrm.reg' when we're encoding memory expression.
    // This is extension of the op code.
    // SDM notes this after the opcode as /<register number>, for example
    // 8F /0 -> pop,  opcode = 8F, modrm.reg set to 0 (RAX)
    // FF /6 -> push, opcode = FF, modrm.reg set to 6 (RSI)
    uint8_t rm_op;
    uint8_t reg;
    uint8_t imm8;
    uint8_t imm32;

} X64OpUnary;

static inline x64opunary_has_imm(const X64OpUnary op) {
    return op.imm8 || op.imm32;
}

const X64OpUnary X64Op_Pop = {
    .reg = 0x58,
    // TODO: Cannot encode 32-bit operand size.
    // NOTE: Notated as 8F /0 in SDM.
    .rm = 0x8F, .rm_op = 0,
};

const X64OpUnary X64Op_Push = {
    .reg = 0x50,
    // NOTE: Notated as FF /6 in SDM.
    .rm = 0xFF, .rm_op = 6,
    .imm8 = 0x6A,
    .imm32 = 0x68,
};

//
//
//

typedef struct X64Inst {
    uint8_t bytes[
        3 + // prefixes
        3 + // opcode
        1 + // mod r/m
        1 + // sib
        8 + // displacement (some rare instructions take 8B displacement)
        8 + // immediate    (some rare instructions take 8B immediate)
        0
    ];
    uint8_t count;
    const char* error;
} X64Inst;

//
//
//

static inline int8_t
x64imm_get_size(uint64_t imm)
{
    if (imm <= 0xff) {
        return 1;
    } else if (imm <= 0xffffffffull) {
        return 4;
    } else {
        return 8;
    }
}

// 'w' operand size is 64-bit
// 'r' extension of modrm.reg
// 'x' extension of sib.index
// 'b' extension of modrm.rm, sib.base or opcode reg field
static inline uint8_t
x64rex(int8_t w, int8_t r, uint8_t x, uint8_t b) {
    // bits: 0100 W R X B
    uint8_t wrxb = (w & 1) << 3 | (r & 1) << 2 | (x & 1) << 1 | (b & 1) << 0;
    if (wrxb) {
        return 0b01000000 | wrxb;
    }
    return 0;
}

// 'mode'
//   - 00 - memory expression with no displacement
//   - 01 - memory expression with 8-bit displacement
//   - 10 - memory expression with 32-bit displacement
//   - 11 - register
// 'reg' is reg/opcode field
//   - specifies either a register number or three more bits of opcode information.
//     - for exampel PUSH is FF opcode, with value 6 in this field.
// 'rm'
//   - can specify a register as an operand or it can be combined with
//     the mod field to encode an addressing mode. Sometimes, certain
//     combinations of the mod field and the rm field are used to express
//     opcode information for some instructions.
static inline uint8_t
x64modrm(X64ModRMMode mode, X64Reg reg, X64Reg rm) {
    X64_ASSERT_DEBUG(mode >= 0 && mode < 4);
    x64reg_check(reg);
    x64reg_check(rm);
    return
        (mode << 6) |
        (((reg - 1) & 7) << 3) |
        ((rm - 1) & 7);
}

static inline uint8_t
x64sib(X64Scale scale, X64Reg index, X64Reg base) {
    X64_ASSERT_DEBUG(scale >= 0 && scale < 4);
    x64reg_check(index);
    x64reg_check(base);
    return
        (scale << 6) |
        (((index - 1) & 7) << 3) |
        ((base - 1) & 7);
}

static inline uint8_t
x64op_reg(int16_t op, X64Reg reg) {
    X64_ASSERT_DEBUG(op != -1);
    x64reg_check(reg);
    return op | ((reg - 1) & 7);
}

//
// Full instruction encoders
//

static inline uint8_t*
x64e_bytes_(uint8_t* it, uint8_t* bytes, int bytes_count) {
    while (bytes_count) {
        *it++ = *bytes++;
        --bytes_count;
    }
    return it;
}

// Mem/Reg (rm_reg)
// Reg/Mem (reg_rm)
// Mem/Imm (some of rm_imm, others are encoded with x64e_modrm_)
// Instruction with memory expression operand.
static inline uint8_t*
x64e_modrm_sib_disp_(uint8_t* it, X64Size size, int opcode, X64Reg reg, X64Reg base, X64Reg index, X64Scale scale, uint64_t displacement, char** error)
{
    X64_ASSERT_DEBUG(opcode != -1);

    int modrm_mode = -1;
    int modrm_reg = reg;
    int modrm_rm = base;

    bool sib = false;
    int sib_scale = 0;
    int sib_index = 0;
    int sib_base = 0;

    uint8_t rex = 0;

    int8_t displacement_size = 0;
    if (displacement == 0) {
        displacement_size = 0;
        modrm_mode = X64ModRM_Indirect;
    } else if (displacement < 0x100) {
        displacement_size = 1;
        modrm_mode = X64ModRM_IndirectDisp8;
    } else {
        displacement_size = 4;
        modrm_mode = X64ModRM_IndirectDisp32;
    }

    if (base == X64_RIP)
    {
        if (index != 0 || scale != 0) {
            *error = "index and scale must be 0 in when base is RIP";
            return NULL;
        }
        // Special case.
        // Forcing mode to Indirect, and displacement size to 4.
        modrm_mode = X64ModRM_Indirect;
        modrm_rm = X64_RBP;
        displacement_size = 4;
    }
    else if (index == 0)
    {
        if (scale != 0) {
            X64_ERROR("scale must be set to X1");
        }

        // Signal no index.
        sib_index = X64_RSP;

        if (base == 0) {
            // No base, no index, assuming absolute addressing.
            sib = true;
            modrm_rm = X64_RSP;
            sib_base = X64_RBP;
            modrm_mode = X64ModRM_Indirect;
            displacement_size = 4;
        } else if (base == X64_RBP || base == X64_R13) {
            // RBS-base, no index.
            if (modrm_mode == X64ModRM_Indirect) {
                // Special case.
                X64_ASSERT_DEBUG(displacement == 0);
                displacement_size = 1;
                modrm_mode = X64ModRM_IndirectDisp8;
            }
        } else if (base == X64_RSP || base == X64_R12) {
            // RSP-base, no index.
            // Because RSP has special meaning in modrm.rm,
            // we need to force SIB here and do it through sib.base.
            sib = true;
            modrm_rm = X64_RSP;
            sib_base = base;
        } else {
            // Base only, no index.
            // Other-than RBP base, no SIB.
            X64_ASSERT_DEBUG(sib == false);
            X64_ASSERT_DEBUG(modrm_rm);
        }
    }
    else if (index == X64_RSP)
    {
        // This is a special feature provided on assembler level.
        // If we want to index by RSP, we can only do so by setting it as sib.base.
        // That means that sib.scale has to be set to X1.
        if (scale != X64_X1) {
            *error = "cannot index by RSP with scale other than 1";
            return NULL;
        }

        // Same as branch index == 0 && base == X64_RSP.
        sib = true;
        modrm_rm = X64_RSP;
        sib_base = X64_RSP;
        if (base == 0) {
            sib_index = X64_RSP;
        } else {
            sib_index = base;
        }
    }
    else
    {
        sib = true;
        modrm_rm = X64_RSP;

        sib_index = index;
        sib_scale = scale;
        sib_base = base;
        if (base == 0) {
            // Flag we're using no base.
            sib_base = X64_RBP;
            // We have to switch mode to 0b00 and force displacement_size to 4.
            modrm_mode = X64ModRM_Indirect;
            displacement_size = 4;
        } else if (base == X64_RBP || base == X64_R13) {
            // RBS-base, no index.
            if (modrm_mode == X64ModRM_Indirect) {
                // Special case.
                X64_ASSERT_DEBUG(displacement == 0);
                displacement_size = 1;
                modrm_mode = X64ModRM_IndirectDisp8;
            }
        }
    }

    rex = x64rex(
        size == X64_S64,
        x64reg_is_int_ext(reg),
        sib && x64reg_is_int_ext(sib_index),
        sib
            ? x64reg_is_int_ext(sib_base)
            : x64reg_is_int_ext(modrm_rm));
    if (rex) *it++ = rex;

    *it++ = opcode;
    *it++ = x64modrm(modrm_mode, modrm_reg, modrm_rm);
    if (sib) *it++ = x64sib(sib_scale, sib_index, sib_base);
    it = x64e_bytes_(it, (uint8_t*)&displacement, displacement_size);

    return it;
}

// Reg/Imm (rmX_immX)
// Reg and OpCode extension in ModRm
static inline uint8_t*
x64e_modrm_(uint8_t* it, X64Size size, int opcode, int opcode_ext, X64Reg reg)
{
    X64_ASSERT_DEBUG(opcode != -1);
    X64_ASSERT_DEBUG(reg != 0);

    // This encodes:
    // 1. OpCode
    // 2. ModRm with Mode=11, Reg=opcode_ext, RM=reg
    // 3. No SIB it seems.
    // TODO: Test variants of this with ModRm/SIB registers.

    uint8_t rex = x64rex(size == X64_S64, 0, 0, x64reg_is_int_ext(reg));
    if (rex) *it++ = rex;
    *it++ = opcode;
    *it++ = x64modrm(X64ModRM_Direct, opcode_ext + 1, reg);
    return it;
}

// Reg/Imm (regX_immX)
// Reg in OpCode (hence rex extends it via `.b`)
static inline uint8_t*
x64e_op_reg_(uint8_t* it, X64Size size, int opcode, X64Reg reg)
{
    X64_ASSERT_DEBUG(opcode != -1);

    uint8_t rex = x64rex(size == X64_S64, 0, 0, x64reg_is_int_ext(reg));
    if (rex) *it++ = rex;
    // Encode reg in opcode (bottom 3 bits).
    *it++ = x64op_reg(opcode, reg);

    return it;
}

//
//
//

X64Inst
x64_emit_error(const char* error)
{
    X64_ASSERT_DEBUG(error);
    return (X64Inst){ .error = error };
}

//
//
//


uint8_t*
x64_emit_binary_reg_reg_(uint8_t* it, X64Size size, const X64OpBinary op, X64Operand D, X64Operand S, char** error)
{
    // reg_rm
    // rm8_reg8 -- in case size == X64_S8

    if (D.reg == 0) {
        *error = "destination register cannot be none";
        return 0;
    }

    int16_t opcode = op.reg_rm;
    uint8_t rex = 0;
    if (size == X64_S8) {
        // ML64 seems to prefer rm8_reg8, while
        // GCC prefers reg8_rm8.
#if 0
        if (op.rm8_reg8) {
            opcode = op.rm8_reg8;
            x64o_swap(D, S);
        }
#else
        if (op.reg8_rm8) {
            opcode = op.reg8_rm8;
        }
#endif
    }
    X64_ASSERT_DEBUG(opcode != -1);

    rex = x64rex(size == X64_S64, x64reg_is_int_ext(D.reg), 0, x64reg_is_int_ext(S.reg));
    if (rex) *it++ = rex;
    *it++ = opcode;
    *it++ = x64modrm(X64ModRM_Direct, D.reg, S.reg);
    return it;
}

uint8_t*
x64_emit_binary_reg_imm_(uint8_t* it, X64Size size, const X64OpBinary op, X64Operand D, X64Operand S, char **error)
{
    // This encodes one of two op codes:
    // - reg8_imm8 (or rm8_imm8)
    // - reg32_imm32 (or rm_imm32)
    // In case of rmX_immX variant, we encode:
    // - modrm.mode == 0b11
    // - modrm.reg = op.reg8_imm8_op
    // - modrm.rm = D.reg
    // In case of regX_immX:
    // - we encode D.reg into opcode directly

    // In case this is specified and required, we'll use:
    // reg64_imm64
    // If not defined, but required, we'll raise and error.

    X64_ASSERT_DEBUG(D.kind == X64O_Reg);
    X64_ASSERT_DEBUG(S.kind == X64O_Imm);
    if (D.reg == 0) {
        *error = "destination register cannot be none";
        return 0;
    }

    int imm_size = x64imm_get_size(S.imm);

    // (uint8_t)a -= 400

    switch (size)
    {
        case X64_S8:
            if (imm_size > 1) {
                *error = "immediate value truncated to 8 bits because of size argument";
                return NULL;
            }
            imm_size = 1;
            if (op.reg8_imm8 == -1) {
                it = x64e_modrm_(it, X64_S32, op.rm8_imm8, op.rm8_imm8_op, D.reg);
            } else {
                it = x64e_op_reg_(it, X64_S8, op.reg8_imm8, D.reg);
            }
            break;

        case X64_S64:
            if (imm_size > 4) {
                // 64-bit
                if (op.reg64_imm64 == -1) {
                    *error = "64-bit immediate value not supported with this instruction";
                    return NULL;
                }
                it = x64e_op_reg_(it, X64_S64, op.reg64_imm64, D.reg);
                break;
            }
            // Fallthrough.
        case X64_S32:
            // WARNING: X64_S64 falls through here as well.
            if (imm_size == 1 && op.rm_imm8 != -1) {
                // We're using `size` here because we want REX in case we fallthrough
                // from size == X64_S64.
                it = x64e_modrm_(it, size, op.rm_imm8, op.rm_imm8_op, D.reg);
            } else {
                if (imm_size > 4) {
                    *error = "immediate value truncated to 32 bits because of size argument";
                    return NULL;
                }
                imm_size = 4;
                if (size == X64_S32 && op.reg32_imm32 != -1) {
                    // We're not taking this branch in case the size 64 fallsthrough here.
                    // Otherwise we'd have to encode imm64, even if it's way smaller.
                    it = x64e_op_reg_(it, X64_S32, op.reg32_imm32, D.reg);
                } else {
                    // We're using `size` here because we want REX in case we fallthrough
                    // from size == X64_S64.
                    it = x64e_modrm_(it, size, op.rm_imm32, op.rm_imm32_op, D.reg);
                }
            }
            break;

    }

    return x64e_bytes_(it, (uint8_t*)&S.imm, imm_size);
}

uint8_t*
x64_emit_binary_mem_imm_(uint8_t* it, X64Size size, const X64OpBinary op, X64Operand D, X64Operand S, char** error)
{
    X64_ASSERT(D.kind == X64O_Mem && S.kind == X64O_Imm);

    int8_t imm_size = x64imm_get_size(S.imm);

    int opcode = -1;
    int opcode_ext = 0;

    switch (size)
    {
        case X64_S8:
            if (imm_size > 1) {
                *error = "immediate value truncated to 8 bits because of size argument";
                return NULL;
            }
            imm_size = 1;
            opcode = op.rm8_imm8;
            opcode_ext = op.rm8_imm8_op;
            break;

        case X64_S64:
            if (imm_size > 4) {
                *error = "operation mem64, imm64 is not supported";
                return NULL;
            }
            // Fallthrough as we'll use rm_imm8 or rm_imm32 with rex (produced by x64e used).
        case X64_S32:
            // TODO: Check whether SDefault works here as it's supposed to.
            if (imm_size == 1 && op.rm_imm8 != -1) {
                opcode = op.rm_imm8;
                opcode_ext = op.rm_imm8_op;
            } else {
                if (imm_size > 4) {
                    *error = "immediate value truncated to 32 bits because of size argument";
                    return NULL;
                }
                opcode = op.rm_imm32;
                opcode_ext = op.rm_imm32_op;
                imm_size = 4;
            }
            break;
    }

    it = x64e_modrm_sib_disp_(it,
        size,
        opcode,
        opcode_ext + 1,
        D.mem.base,
        D.mem.index,
        D.mem.scale,
        D.mem.displacement,
        error);
    return x64e_bytes_(it, (uint8_t*)&S.imm, imm_size);
}

uint8_t*
x64_emit_binary_reg_mem_(uint8_t* it, X64Size size, const X64OpBinary op, X64Operand D, X64Operand S, char** error)
{
    int opcode = 0;
    switch (x64o_pair(D.kind, S.kind))
    {
        case x64o_pair(X64O_Reg, X64O_Mem):
            // All good.
            opcode = size == X64_S8
                ? op.reg8_rm8
                : op.reg_rm;
            break;
        case x64o_pair(X64O_Mem, X64O_Reg):
            x64o_swap(D, S);
            opcode = size == X64_S8
                ? op.rm8_reg8
                : op.rm_reg;
            break;
        default:
            X64_ERROR("invalid operands");
            return it;
    }

    if (opcode == -1) {
        X64_ERROR("opcode is not defined");
        return it;
    }

    return x64e_modrm_sib_disp_(it, size, opcode, D.reg, S.mem.base, S.mem.index, S.mem.scale, S.mem.displacement, error);
}

X64Inst
x64_emit_binary(X64Size size, const X64OpBinary op, X64Operand D, X64Operand S)
{
    X64Inst inst = {0};
    uint8_t* it = inst.bytes;

    char* error = "uknown error";
    switch (x64o_pair(D.kind, S.kind))
    {
        case x64o_pair(X64O_Reg, X64O_Reg):
            it = x64_emit_binary_reg_reg_(it, size, op, D, S, &error);
            break;

        case x64o_pair(X64O_Reg, X64O_Imm):
            it = x64_emit_binary_reg_imm_(it, size, op, D, S, &error);
            break;

        case x64o_pair(X64O_Mem, X64O_Reg):
        case x64o_pair(X64O_Reg, X64O_Mem):
            it = x64_emit_binary_reg_mem_(it, size, op, D, S, &error);
            break;

        case x64o_pair(X64O_Mem, X64O_Imm):
            it = x64_emit_binary_mem_imm_(it, size, op, D, S, &error);
            break;


        default:
            X64_ERROR("unexpected arguments");
    }

    if (it == 0) {
        return x64_emit_error(error);
    }

    inst.count = it - inst.bytes;
    return inst;
}

X64Inst x64_emit_unary(X64OpUnary op, X64Operand D)
{
    X64Inst inst = {0};
    uint8_t* it = inst.bytes;

    char* error = "unknown error";
    uint8_t rex = 0;
    switch (D.kind)
    {
        case X64O_Reg:
            if (D.reg == 0) {
                return x64_emit_error("invalid register");
            }
            rex = x64rex(0, 0, 0, x64reg_is_int_ext(D.reg));
            if (rex) *it++ = rex;
            *it++ = op.reg | (D.reg - 1) & 7;
            break;

        case X64O_Imm: {
            if (!x64opunary_has_imm(op)) {
                return x64_emit_error("immediate values are not supported with this operation");
            }
            if (op.imm8 && D.imm <= 0xFF) {
                *it++ = op.imm8;
                it = x64e_bytes_(it, (uint8_t*)&D.imm, 1);
            } else if (op.imm32 && D.imm <= 0xFFFFffff) {
                *it++ = op.imm32;
                it = x64e_bytes_(it, (uint8_t*)&D.imm, 4);
            } else {
                return x64_emit_error("32-bit immediate is maximum");
            }
            break;
        }

        case X64O_Mem: {
            it = x64e_modrm_sib_disp_(it, X64_SDefault, op.rm, op.rm_op + 1, D.mem.base, D.mem.index, D.mem.scale, D.mem.displacement, &error);
            if (it == 0) {
                return x64_emit_error(error);
            }
            break;
        }

        default:
            return x64_emit_error("invalid operand");
    }

    inst.count = it - inst.bytes;
    return inst;
}

//
//
//

static inline X64Inst x64_mov(X64Size size, X64Operand D, X64Operand S) { return x64_emit_binary(size, X64Op_Mov, D, S); }
static inline X64Inst x64_sub(X64Size size, X64Operand D, X64Operand S) { return x64_emit_binary(size, X64Op_Sub, D, S); }
static inline X64Inst x64_add(X64Size size, X64Operand D, X64Operand S) { return x64_emit_binary(size, X64Op_Add, D, S); }
static inline X64Inst x64_and(X64Size size, X64Operand D, X64Operand S) { return x64_emit_binary(size, X64Op_And, D, S); }
static inline X64Inst  x64_or(X64Size size, X64Operand D, X64Operand S) { return x64_emit_binary(size, X64Op_Or,  D, S); }
static inline X64Inst x64_xor(X64Size size, X64Operand D, X64Operand S) { return x64_emit_binary(size, X64Op_Xor, D, S); }

static inline X64Inst x64_pop(X64Operand D)  { return x64_emit_unary(X64Op_Pop, D); }
static inline X64Inst x64_push(X64Operand S) { return x64_emit_unary(X64Op_Push, S); }

// TODO: What about '0xCB RET Far return to calling procedure.'?
static inline X64Inst x64_ret() { return (X64Inst){ .bytes = { 0xC3 }, .count = 1 }; }

// TODO: `lea`
// TODO: `not`
// TODO: `shl`
// TODO: `shr`
// TODO: `sal`
// TODO: `sar`
// TODO: `int3`
// TODO: `call reg`
// TODO: `call imm64`
// TODO: `imul` (result in rdx and rax)
//  - https://youtu.be/ieuUHIWaIqM?list=PL0C5C980A28FEE68D&t=340
//  - there's single operand, double operand and tripple operand versions
// TODO: `idiv`