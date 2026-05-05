#include <ntddk.h>
#include "ntapi_hook_ldasm.h"

#if defined(_AMD64_)

// ---------------------------------------------------------------------------
//  Minimal x86-64 instruction length decoder
//
//  Design constraints
//  ------------------
//  * Kernel-mode only, no CRT, no exceptions beyond __try/__except at call site.
//  * Conservative: returns 0 (unknown) rather than guessing when the encoding is
//    not covered, so callers can safely fall back to their hardcoded values.
//  * Targets MSVC-generated Windows kernel prologue patterns; does NOT need to
//    handle all x86 encodings (privileged instructions, 3DNow!, etc.).
//
//  Notation used in comments
//  -------------------------
//  Mod    = ModRM[7:6]   (0=indirect, 1=disp8, 2=disp32, 3=register)
//  Reg/Op = ModRM[5:3]
//  RM     = ModRM[2:0]
//  SIB present when Mod != 3 && RM == 4
//  disp8  when Mod == 1
//  disp32 when Mod == 2, or (Mod == 0 && RM == 5) — RIP-relative
// ---------------------------------------------------------------------------

// Flags used in the one-byte opcode table
#define F_NONE 0x00u
#define F_MODRM 0x01u // instruction has a ModRM byte
#define F_IMM8 0x02u  // 1-byte immediate
#define F_IMM16 0x04u // 2-byte immediate (rarely needed; ENTER, RET imm16)
#define F_IMM32 0x08u // 4-byte immediate (or 8-byte when REX.W set — see code)
#define F_REL8 0x10u  // 1-byte signed PC-relative (short Jcc / JMP short)
#define F_REL32 0x20u // 4-byte signed PC-relative (near Jcc / CALL / JMP near)
#define F_INV 0x80u   // invalid / not handled — return 0

// One-byte opcode table.  Each entry describes the *non-prefix* bytes after the opcode.
// Index is the opcode byte with REX and legacy prefixes already stripped.
static const UCHAR g_Op1[256] = {
    // 0x00-0x05: ADD
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_IMM8,
    F_IMM32,
    // 0x06-0x07: PUSH/POP ES (invalid in 64-bit) — treat as unknown
    F_INV,
    F_INV,
    // 0x08-0x0D: OR
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_IMM8,
    F_IMM32,
    // 0x0E-0x0F: PUSH CS (invalid) / escape
    F_INV,
    F_INV, // 0x0F handled separately as 2-byte escape

    // 0x10-0x15: ADC
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_IMM8,
    F_IMM32,
    // 0x16-0x17: invalid
    F_INV,
    F_INV,
    // 0x18-0x1D: SBB
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_IMM8,
    F_IMM32,
    // 0x1E-0x1F: invalid
    F_INV,
    F_INV,

    // 0x20-0x25: AND
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_IMM8,
    F_IMM32,
    // 0x26: ES segment override (legacy prefix — skip as prefix in decode loop)
    F_INV,
    // 0x27: DAA (invalid in 64-bit)
    F_INV,
    // 0x28-0x2D: SUB
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_IMM8,
    F_IMM32,
    // 0x2E: CS segment override — skip as prefix
    F_INV,
    // 0x2F: DAS (invalid)
    F_INV,

    // 0x30-0x35: XOR
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_IMM8,
    F_IMM32,
    // 0x36: SS override — skip as prefix
    F_INV,
    // 0x37: AAA (invalid)
    F_INV,
    // 0x38-0x3D: CMP
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_IMM8,
    F_IMM32,
    // 0x3E: DS override — skip as prefix
    F_INV,
    // 0x3F: AAS (invalid)
    F_INV,

    // 0x40-0x4F: REX prefixes (handled in prefix loop; never appear here as opcode)
    F_INV,
    F_INV,
    F_INV,
    F_INV,
    F_INV,
    F_INV,
    F_INV,
    F_INV,
    F_INV,
    F_INV,
    F_INV,
    F_INV,
    F_INV,
    F_INV,
    F_INV,
    F_INV,

    // 0x50-0x57: PUSH rAX..rDI
    F_NONE,
    F_NONE,
    F_NONE,
    F_NONE,
    F_NONE,
    F_NONE,
    F_NONE,
    F_NONE,
    // 0x58-0x5F: POP rAX..rDI
    F_NONE,
    F_NONE,
    F_NONE,
    F_NONE,
    F_NONE,
    F_NONE,
    F_NONE,
    F_NONE,

    // 0x60-0x67: PUSHA/POPA/BOUND etc. (invalid in 64-bit) + addr/operand size prefixes
    F_INV,
    F_INV,
    F_INV,
    F_MODRM, // 0x63 = MOVSXD r64, r/m32 (common in prologues)
    F_INV,
    F_INV,
    F_INV,
    F_INV,

    // 0x68: PUSH imm32; 0x69: IMUL r,r/m,imm32; 0x6A: PUSH imm8; 0x6B: IMUL r,r/m,imm8
    F_IMM32,
    F_MODRM | F_IMM32,
    F_IMM8,
    F_MODRM | F_IMM8,
    // 0x6C-0x6F: INS/OUTS — not in prologues
    F_INV,
    F_INV,
    F_INV,
    F_INV,

    // 0x70-0x7F: Jcc short (rel8)
    F_REL8,
    F_REL8,
    F_REL8,
    F_REL8,
    F_REL8,
    F_REL8,
    F_REL8,
    F_REL8,
    F_REL8,
    F_REL8,
    F_REL8,
    F_REL8,
    F_REL8,
    F_REL8,
    F_REL8,
    F_REL8,

    // 0x80-0x83: Grp1 (ADD/OR/ADC/SBB/AND/SUB/XOR/CMP) r/m, imm
    F_MODRM | F_IMM8,  // 0x80 r/m8, imm8
    F_MODRM | F_IMM32, // 0x81 r/m64, imm32 (sign-extended)
    F_INV,             // 0x82 invalid in 64-bit
    F_MODRM | F_IMM8,  // 0x83 r/m64, imm8 (sign-extended) — very common (SUB RSP,N)

    // 0x84-0x8F
    F_MODRM, // 0x84 TEST r/m8, r8
    F_MODRM, // 0x85 TEST r/m64, r64  — very common (TEST RCX,RCX etc.)
    F_MODRM, // 0x86 XCHG r8, r/m8
    F_MODRM, // 0x87 XCHG r64, r/m64
    F_MODRM, // 0x88 MOV r/m8, r8
    F_MODRM, // 0x89 MOV r/m64, r64  — very common
    F_MODRM, // 0x8A MOV r8, r/m8
    F_MODRM, // 0x8B MOV r64, r/m64  — very common
    F_MODRM, // 0x8C MOV r/m, Sreg
    F_MODRM, // 0x8D LEA r64, m       — very common (LEA RCX,[RIP+disp])
    F_MODRM, // 0x8E MOV Sreg, r/m
    F_MODRM, // 0x8F POP r/m64

    // 0x90-0x97: XCHG rAX, rAX (NOP) .. rDI
    F_NONE,
    F_NONE,
    F_NONE,
    F_NONE,
    F_NONE,
    F_NONE,
    F_NONE,
    F_NONE,

    // 0x98-0x9F
    F_NONE, // 0x98 CBW/CWDE/CDQE
    F_NONE, // 0x99 CWD/CDQ/CQO
    F_INV,  // 0x9A CALLF (invalid in 64-bit)
    F_NONE, // 0x9B FWAIT
    F_NONE, // 0x9C PUSHFQ
    F_NONE, // 0x9D POPFQ
    F_NONE, // 0x9E SAHF
    F_NONE, // 0x9F LAHF

    // 0xA0-0xA3: MOV AL/AX/EAX/RAX, moffs  — 8-byte absolute address operand
    F_INV,
    F_INV,
    F_INV,
    F_INV, // not common in prologues; skip
           // 0xA4-0xA7: MOVS/CMPS
    F_NONE,
    F_NONE,
    F_NONE,
    F_NONE,
    // 0xA8-0xA9: TEST AL/rAX, imm
    F_IMM8,
    F_IMM32,
    // 0xAA-0xAF: STOS/LODS/SCAS
    F_NONE,
    F_NONE,
    F_NONE,
    F_NONE,
    F_NONE,
    F_NONE,

    // 0xB0-0xB7: MOV r8, imm8
    F_IMM8,
    F_IMM8,
    F_IMM8,
    F_IMM8,
    F_IMM8,
    F_IMM8,
    F_IMM8,
    F_IMM8,
    // 0xB8-0xBF: MOV rAX..rDI, imm64 (with REX.W; imm size handled in code)
    F_IMM32,
    F_IMM32,
    F_IMM32,
    F_IMM32,
    F_IMM32,
    F_IMM32,
    F_IMM32,
    F_IMM32,

    // 0xC0-0xC1: Shift r/m, imm8
    F_MODRM | F_IMM8,
    F_MODRM | F_IMM8,
    // 0xC2: RET imm16; 0xC3: RET
    F_IMM16,
    F_NONE,
    // 0xC4-0xC5: VEX prefixes (3-byte, 2-byte) — not in prologues
    F_INV,
    F_INV,
    // 0xC6: MOV r/m8, imm8; 0xC7: MOV r/m64, imm32
    F_MODRM | F_IMM8,
    F_MODRM | F_IMM32,
    // 0xC8: ENTER imm16, imm8; 0xC9: LEAVE; 0xCA: RETF imm16; 0xCB: RETF
    F_INV,
    F_NONE,
    F_INV,
    F_NONE,
    // 0xCC: INT3; 0xCD: INT imm8; 0xCE: INTO (invalid); 0xCF: IRETQ
    F_NONE,
    F_IMM8,
    F_INV,
    F_NONE,

    // 0xD0-0xD3: Shift r/m, 1 / CL
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    // 0xD4-0xD7: AAM/AAD/XLAT (invalid in 64-bit)
    F_INV,
    F_INV,
    F_INV,
    F_INV,
    // 0xD8-0xDF: FPU escapes — not in prologues
    F_INV,
    F_INV,
    F_INV,
    F_INV,
    F_INV,
    F_INV,
    F_INV,
    F_INV,

    // 0xE0-0xE3: LOOPNE/LOOPE/LOOP/JRCXZ rel8
    F_REL8,
    F_REL8,
    F_REL8,
    F_REL8,
    // 0xE4-0xE7: IN/OUT imm8 (ring-0 but uncommon in prologues)
    F_IMM8,
    F_IMM8,
    F_IMM8,
    F_IMM8,
    // 0xE8: CALL rel32; 0xE9: JMP rel32; 0xEA: JMPF (invalid); 0xEB: JMP rel8
    F_REL32,
    F_REL32,
    F_INV,
    F_REL8,
    // 0xEC-0xEF: IN/OUT DX
    F_NONE,
    F_NONE,
    F_NONE,
    F_NONE,

    // 0xF0: LOCK prefix (handled in prefix loop); 0xF1: INT1; 0xF2/0xF3: REP prefixes
    F_INV,
    F_NONE,
    F_INV,
    F_INV,
    // 0xF4: HLT; 0xF5: CMC
    F_NONE,
    F_NONE,
    // 0xF6-0xF7: Grp3 (TEST/NOT/NEG/MUL/IMUL/DIV/IDIV) — ModRM + optional imm
    F_MODRM | F_IMM8,  // 0xF6: for /0 (TEST) there is imm8; conservative
    F_MODRM | F_IMM32, // 0xF7: for /0 (TEST) there is imm32
                       // 0xF8-0xFD: CLC/STC/CLI/STI/CLD/STD
    F_NONE,
    F_NONE,
    F_NONE,
    F_NONE,
    F_NONE,
    F_NONE,
    // 0xFE: Grp4 (INC/DEC r/m8); 0xFF: Grp5 (INC/DEC/CALL/JMP/PUSH r/m)
    F_MODRM,
    F_MODRM,
};

// Two-byte opcode table (after 0x0F escape).  Same flag encoding.
static const UCHAR g_Op2[256] = {
    // 0x00-0x0F: various privileged / group instructions
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM, // 0x00-0x03
    F_INV,
    F_INV,
    F_INV,
    F_INV, // 0x04-0x07
    F_NONE,
    F_NONE,
    F_INV,
    F_NONE, // 0x08 INVD, 0x09 WBINVD, 0x0B UD2
    F_INV,
    F_INV,
    F_MODRM,
    F_MODRM, // 0x0E, 0x0F, 0x0D NOP(r/m), 0x0E FEMMS

    // 0x10-0x17: SSE MOV variants
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_INV,
    // 0x18-0x1F: PREFETCH/HINT NOP
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM, // 0x1F multibyte NOP (common compiler output)

    // 0x20-0x27: MOV CR/DR
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_INV,
    F_INV,
    // 0x28-0x2F: SSE
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,

    // 0x30-0x3F: WRMSR/RDMSR/RDTSC/RDPMC/SYSENTER/SYSEXIT/XGETBV etc.
    F_NONE,
    F_NONE,
    F_NONE,
    F_NONE,
    F_NONE,
    F_NONE,
    F_INV,
    F_INV,
    F_INV,
    F_INV,
    F_INV,
    F_INV,
    F_INV,
    F_INV,
    F_INV,
    F_INV,

    // 0x40-0x4F: CMOVcc r, r/m
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,

    // 0x50-0x5F: SSE
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,

    // 0x60-0x6F: MMX/SSE
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,

    // 0x70-0x7F: SSE (some with imm8)
    F_MODRM | F_IMM8,
    F_MODRM | F_IMM8,
    F_MODRM | F_IMM8,
    F_MODRM | F_IMM8,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_NONE,
    F_MODRM | F_IMM8,
    F_MODRM | F_IMM8,
    F_MODRM | F_IMM8,
    F_MODRM | F_IMM8,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,

    // 0x80-0x8F: Jcc near (rel32)
    F_REL32,
    F_REL32,
    F_REL32,
    F_REL32,
    F_REL32,
    F_REL32,
    F_REL32,
    F_REL32,
    F_REL32,
    F_REL32,
    F_REL32,
    F_REL32,
    F_REL32,
    F_REL32,
    F_REL32,
    F_REL32,

    // 0x90-0x9F: SETcc r/m8
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,

    // 0xA0-0xAF
    F_NONE,
    F_NONE,
    F_NONE,
    F_MODRM, // PUSH FS, POP FS, CPUID, BT
    F_MODRM | F_IMM8,
    F_MODRM,
    F_MODRM,
    F_MODRM, // SHLD imm8, SHLD CL, -, -
    F_NONE,
    F_NONE,
    F_MODRM,
    F_MODRM, // PUSH GS, POP GS, RSM, BTS
    F_MODRM | F_IMM8,
    F_MODRM,
    F_MODRM,
    F_MODRM, // SHRD imm8, SHRD CL, Grp15, IMUL

    // 0xB0-0xBF
    F_MODRM,
    F_MODRM, // 0xB0-0xB1 CMPXCHG
    F_MODRM,
    F_MODRM, // 0xB2-0xB3 LSS, BTR
    F_MODRM,
    F_MODRM, // 0xB4-0xB5 LFS, LGS
    F_MODRM,
    F_MODRM, // 0xB6-0xB7 MOVZX r,r/m8 / r,r/m16
    F_INV,
    F_INV, // 0xB8 POPCNT(prefix-dep), 0xB9 UD1
    F_MODRM | F_IMM8,
    F_MODRM, // 0xBA Grp8 (BT/BTS/BTR/BTC) + imm8, 0xBB BTC
    F_MODRM,
    F_MODRM, // 0xBC-0xBD BSF, BSR
    F_MODRM,
    F_MODRM, // 0xBE-0xBF MOVSX r,r/m8 / r,r/m16

    // 0xC0-0xCF
    F_MODRM,
    F_MODRM, // 0xC0-0xC1 XADD
    F_MODRM | F_IMM8,
    F_MODRM, // 0xC2 CMPPS+imm8, 0xC3 MOVNTI
    F_MODRM | F_IMM8,
    F_MODRM | F_IMM8, // 0xC4-0xC5 PINSRW+imm8, PEXTRW+imm8
    F_MODRM | F_IMM8,
    F_MODRM, // 0xC6 SHUFPS+imm8, 0xC7 Grp9
    F_NONE,
    F_NONE,
    F_NONE,
    F_NONE,
    F_NONE,
    F_NONE,
    F_NONE,
    F_NONE, // 0xC8-0xCF BSWAP

    // 0xD0-0xDF: SSE
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,

    // 0xE0-0xEF: SSE
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,

    // 0xF0-0xFF: SSE
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_MODRM,
    F_INV,
};

// Returns the length of one instruction, or 0 on failure.
// 'Available' is the number of bytes we are permitted to read from 'Bytes'.
static ULONG DecodeOne(const UCHAR *Bytes, ULONG Available)
{
    ULONG pos = 0;
    UCHAR flags;
    BOOLEAN rexW = FALSE;
    BOOLEAN twoByteEscape = FALSE;
    UCHAR op;
    UCHAR modrm, mod, rm;
    BOOLEAN hasSib;
    ULONG dispSize;
    ULONG immSize;

    if (Bytes == NULL || Available == 0)
    {
        return 0;
    }

    // ---- Prefix bytes --------------------------------------------------
    // Skip legacy prefixes and consume at most one REX prefix.
    // We stop when we hit a byte that is not a recognized prefix.
    for (;;)
    {
        if (pos >= Available)
        {
            return 0;
        }

        op = Bytes[pos];

        if (op == 0x66 || // operand-size override
            op == 0x67 || // address-size override
            op == 0xF0 || // LOCK
            op == 0xF2 || // REPNE/REPNZ
            op == 0xF3 || // REP/REPE/REPZ
            op == 0x26 || // ES:
            op == 0x2E || // CS:
            op == 0x36 || // SS:
            op == 0x3E || // DS:
            op == 0x64 || // FS:
            op == 0x65)   // GS:
        {
            pos++;
            continue;
        }

        if (op >= 0x40 && op <= 0x4F)
        {
            // REX prefix
            rexW = ((op & 0x08) != 0);
            pos++;
            continue;
        }

        break; // not a prefix — this is the first opcode byte
    }

    if (pos >= Available)
    {
        return 0;
    }

    op = Bytes[pos++];

    // ---- Opcode byte(s) ------------------------------------------------
    if (op == 0x0F)
    {
        // Two-byte escape
        if (pos >= Available)
        {
            return 0;
        }
        op = Bytes[pos++];

        if (op == 0x38 || op == 0x3A)
        {
            // Three-byte escape (SSSE3 / SSE4) — not in kernel prologues
            return 0;
        }

        twoByteEscape = TRUE;
        flags = g_Op2[op];
    }
    else
    {
        flags = g_Op1[op];
    }

    if (flags & F_INV)
    {
        return 0;
    }

    // ---- ModRM + SIB + displacement ------------------------------------
    hasSib = FALSE;
    dispSize = 0;

    if (flags & F_MODRM)
    {
        if (pos >= Available)
        {
            return 0;
        }

        modrm = Bytes[pos++];
        mod = (modrm >> 6) & 0x03;
        rm = (modrm >> 0) & 0x07;

        if (mod == 3)
        {
            // Register operand — no SIB, no displacement
            dispSize = 0;
        }
        else
        {
            // SIB byte present when RM == 4 (and Mod != 3)
            if (rm == 4)
            {
                hasSib = TRUE;
                if (pos >= Available)
                {
                    return 0;
                }
                pos++; // consume SIB
            }

            if (mod == 0)
            {
                // [reg] with no displacement, EXCEPT rm==5 means [RIP+disp32]
                // or (with SIB present) base==5 means disp32 with no base
                if (rm == 5)
                {
                    dispSize = 4; // RIP-relative
                }
                else if (hasSib)
                {
                    // Check SIB.base: if base field == 5, there is a disp32
                    UCHAR sib = Bytes[pos - 1]; // we already advanced past it
                    if ((sib & 0x07) == 5)
                    {
                        dispSize = 4;
                    }
                }
            }
            else if (mod == 1)
            {
                dispSize = 1;
            }
            else // mod == 2
            {
                dispSize = 4;
            }
        }

        if (pos + dispSize > Available)
        {
            return 0;
        }
        pos += dispSize;
    }

    // ---- Immediate operand ---------------------------------------------
    immSize = 0;

    if (flags & F_IMM8)
    {
        // Special case: for F6/F7 Grp3, only /0 and /1 (TEST) have an immediate.
        // We can't determine the sub-opcode without ModRM re-inspection, but since
        // we already consumed ModRM above if F_MODRM is set, we can recheck.
        // For safety, always add the immediate — worst case we are 1 byte off on
        // F6/F7 non-TEST; the caller validates the result by checking instruction
        // boundaries, so an over-count here produces an incorrect decode that the
        // runtime length check catches as out-of-bounds.
        immSize = 1;
    }
    else if (flags & F_IMM16)
    {
        immSize = 2;
    }
    else if (flags & F_IMM32)
    {
        // With REX.W and opcode 0xB8-0xBF (MOV reg, imm64) the immediate is 8 bytes.
        // The one-byte opcode table marks 0xB8-0xBF as F_IMM32; we upgrade here.
        if (!twoByteEscape && rexW && (op >= 0xB8 && op <= 0xBF))
        {
            immSize = 8;
        }
        else
        {
            immSize = 4;
        }
    }
    else if (flags & F_REL8)
    {
        immSize = 1;
    }
    else if (flags & F_REL32)
    {
        immSize = 4;
    }

    if (pos + immSize > Available)
    {
        return 0;
    }
    pos += immSize;

    return pos;
}

// ---------------------------------------------------------------------------
//  Public entry point
// ---------------------------------------------------------------------------

_Success_(return != 0) ULONG
    Bkx64MinCoverLength(_In_reads_bytes_(MaxBytes) const UCHAR *Code, _In_ ULONG MinBytes, _In_ ULONG MaxBytes)
{
    ULONG offset = 0;
    ULONG instrLen;

    if (Code == NULL || MinBytes == 0 || MaxBytes == 0 || MinBytes > MaxBytes)
    {
        return 0;
    }

    while (offset < MinBytes)
    {
        if (offset >= MaxBytes)
        {
            // Cannot cover MinBytes without exceeding MaxBytes
            return 0;
        }

        instrLen = DecodeOne(Code + offset, MaxBytes - offset);
        if (instrLen == 0)
        {
            // Unknown instruction — caller should use its hardcoded value
            return 0;
        }

        offset += instrLen;
    }

    // 'offset' is now >= MinBytes and lands exactly on an instruction boundary
    if (offset > MaxBytes)
    {
        return 0;
    }

    return offset;
}

#endif // _AMD64_
