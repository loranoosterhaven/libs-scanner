
#include "disassembler.h"

// https://source.android.com/devices/tech/dalvik/dalvik-bytecode#instructions
unsigned long instrLenMap[256]{
        2, //00: nop
        2, //01: move vA, vB
        4, //02: move/from16 vAA, vBBBB
        6, //03: move/16 vAAAA, vBBBB
        2, //04: move-wide vA, vB
        4, //05: move-wide/from16 vAA, vBBBB
        6, //06: move-wide/16 vAAAA, vBBBB
        2, //07: move-object vA, vB
        4, //08: move-object/from16 vAA, vBBBB
        6, //09: move-object/16 vAAAA, vBBBB
        2, //0A: move-result vAA
        2, //0B: move-result-wide vAA
        2, //0C: move-result-object vAA
        2, //0D: move-exception vAA
        2, //0E: return-void
        2, //0F: return vAA
        2, //10: return-wide vAA
        2, //11: return-object vAA
        2, //12: const/4 vA, #+B
        4, //13: const/16 vAA, #+BBBB
        6, //14: const vAA, #+BBBBBBBB
        4, //15: const/high16 vAA, #+BBBB0000
        4, //16: const-wide/16 vAA, #+BBBB
        6, //17: const-wide/32 vAA, #+BBBBBBBB
        10, //18: const-wide vAA, #+BBBBBBBBBBBBBBBB
        4, //19: const-wide/high16 vAA, #+BBBB000000000000
        4, //1A: const-string vAA, string@BBBB
        6, //1B: const-string/jumbo vAA, string@BBBBBBBB
        4, //1C: const-class vAA, type@BBBB
        2, //1D: monitor-enter vAA
        2, //1E: monitor-exit vAA
        4, //1F: check-cast vAA, type@BBBB
        4, //20: instance-of vA, vB, type@CCCC
        2, //21: array-length vA, vB
        4, //22: new-instance vAA, type@BBBB
        4, //23: new-array vA, vB, type@CCCC
        6, //24: filled-new-array {vC, vD, vE, vF, vG}, type@BBBB
        6, //25: filled-new-array/range {vCCCC .. vNNNN}, type@BBBB
        6, //26: fill-array-data vAA, +BBBBBBBB
        2, //27: throw vAA
        2, //28: goto +AA
        4, //29: goto/16 +AAAA
        6, //2A: goto/32 +AAAAAAAA
        6, //2B: packed-switch vAA, +BBBBBBBB
        6, //2C: sparse-switch vAA, +BBBBBBBB
        4, //2D: cmpl-float vAA, vBB, vCC
        4, //2E: cmpg-float vAA, vBB, vCC
        4, //2F: cmpl-double vAA, vBB, vCC
        4, //30: cmpg-double vAA, vBB, vCC
        4, //31: cmp-long vAA, vBB, vCC
        4, //32: if-eq vA, vB, +CCCC
        4, //33: if-ne vA, vB, +CCCC
        4, //34: if-lt vA, vB, +CCCC
        4, //35: if-ge vA, vB, +CCCC
        4, //36: if-gt vA, vB, +CCCC
        4, //37: if-le vA, vB, +CCCC
        4, //38: if-eqz vA, vB, +CCCC
        4, //39: if-nez vA, vB, +CCCC
        4, //3A: if-ltz vA, vB, +CCCC
        4, //3B: if-gez vA, vB, +CCCC
        4, //3C: if-gtz vA, vB, +CCCC
        4, //3D: if-lez vA, vB, +CCCC
        2, //3E: unused
        2, //3F: unused
        2, //40: unused
        2, //41: unused
        2, //42: unused
        2, //43: unused
        4, //44: aget vAA, vBB, vCC
        4, //45: aget-wide vAA, vBB, vCC
        4, //46: aget-object vAA, vBB, vCC
        4, //47: aget-boolean vAA, vBB, vCC
        4, //48: aget-byte vAA, vBB, vCC
        4, //49: aget-char vAA, vBB, vCC
        4, //4A: aget-short vAA, vBB, vCC
        4, //4B: aput vAA, vBB, vCC
        4, //4C: aput-wide vAA, vBB, vCC
        4, //4D: aput-object vAA, vBB, vCC
        4, //4E: aput-boolean vAA, vBB, vCC
        4, //4F: aput-byte vAA, vBB, vCC
        4, //50: aput-char vAA, vBB, vCC
        4, //51: aput-short vAA, vBB, vCC
        4, //52: iget vA, vB, field@CCCC
        4, //53: iget-wide vA, vB, field@CCCC
        4, //54: iget-object vA, vB, field@CCCC
        4, //55: iget-boolean vA, vB, field@CCCC
        4, //56: iget-byte vA, vB, field@CCCC
        4, //57: iget-char vA, vB, field@CCCC
        4, //58: iget-short vA, vB, field@CCCC
        4, //59: iput vA, vB, field@CCCC
        4, //5A: iput-wide vA, vB, field@CCCC
        4, //5B: iput-object vA, vB, field@CCCC
        4, //5C: iput-boolean vA, vB, field@CCCC
        4, //5D: iput-byte vA, vB, field@CCCC
        4, //5E: iput-char vA, vB, field@CCCC
        4, //5F: iput-short vA, vB, field@CCCC
        4, //60: sget vAA, field@BBBB
        4, //61: sget-wide vAA, field@BBBB
        4, //62: sget-object vAA, field@BBBB
        4, //63: sget-boolean vAA, field@BBBB
        4, //64: sget-byte vAA, field@BBBB
        4, //65: sget-char vAA, field@BBBB
        4, //66: sget-short vAA, field@BBBB
        4, //67: sput vAA, field@BBBB
        4, //68: sput-wide vAA, field@BBBB
        4, //69: sput-object vAA, field@BBBB
        4, //6A: sput-boolean vAA, field@BBBB
        4, //6B: sput-byte vAA, field@BBBB
        4, //6C: sput-char vAA, field@BBBB
        4, //6D: sput-short vAA, field@BBBB
        6, //6E: invoke-virtual {vC, vD, vE, vF, vG}, meth@BBBB
        6, //6F: invoke-super {vC, vD, vE, vF, vG}, meth@BBBB
        6, //70: invoke-direct {vC, vD, vE, vF, vG}, meth@BBBB
        6, //71: invoke-static {vC, vD, vE, vF, vG}, meth@BBBB
        6, //72: invoke-interface {vC, vD, vE, vF, vG}, meth@BBBB
        2, //73: unused
        6, //74: invoke-virtual/range {vCCCC .. vNNNN}, meth@BBBB
        6, //75: invoke-super/range {vCCCC .. vNNNN}, meth@BBBB
        6, //76: invoke-direct/range {vCCCC .. vNNNN}, meth@BBBB
        6, //77: invoke-static/range {vCCCC .. vNNNN}, meth@BBBB
        6, //78: invoke-interface/range {vCCCC .. vNNNN}, meth@BBBB
        2, //79: unused
        2, //7A: unused
        2, //7B: unop vA, vB
        2, //7C: unop vA, vB
        2, //7D: unop vA, vB
        2, //7E: unop vA, vB
        2, //7F: unop vA, vB
        2, //80: unop vA, vB
        2, //81: unop vA, vB
        2, //82: unop vA, vB
        2, //83: unop vA, vB
        2, //84: unop vA, vB
        2, //85: unop vA, vB
        2, //86: unop vA, vB
        2, //87: unop vA, vB
        2, //88: unop vA, vB
        2, //89: unop vA, vB
        2, //8A: unop vA, vB
        2, //8B: unop vA, vB
        2, //8C: unop vA, vB
        2, //8D: unop vA, vB
        2, //8E: unop vA, vB
        2, //8F: unop vA, vB
        4, //90: add-int vAA, vBB, vCC
        4, //91: sub-int vAA, vBB, vCC
        4, //92: mul-int vAA, vBB, vCC
        4, //93: div-int vAA, vBB, vCC
        4, //94: rem-int vAA, vBB, vCC
        4, //95: and-int vAA, vBB, vCC
        4, //96: or-int vAA, vBB, vCC
        4, //97: xor-int vAA, vBB, vCC
        4, //98: shl-int vAA, vBB, vCC
        4, //99: shr-int vAA, vBB, vCC
        4, //9A: ushr-int vAA, vBB, vCC
        4, //9B: add-long vAA, vBB, vCC
        4, //9C: sub-long vAA, vBB, vCC
        4, //9D: mul-long vAA, vBB, vCC
        4, //9E: div-long vAA, vBB, vCC
        4, //9F: rem-long vAA, vBB, vCC
        4, //A0: and-long vAA, vBB, vCC
        4, //A1: or-long vAA, vBB, vCC
        4, //A2: xor-long vAA, vBB, vCC
        4, //A3: shl-long vAA, vBB, vCC
        4, //A4: shr-long vAA, vBB, vCC
        4, //A5: ushr-long vAA, vBB, vCC
        4, //A6: add-float vAA, vBB, vCC
        4, //A7: sub-float vAA, vBB, vCC
        4, //A8: mul-float vAA, vBB, vCC
        4, //A9: div-float vAA, vBB, vCC
        4, //AA: rem-float vAA, vBB, vCC
        4, //AB: add-double vAA, vBB, vCC
        4, //AC: sub-double vAA, vBB, vCC
        4, //AD: mul-double vAA, vBB, vCC
        4, //AE: div-double vAA, vBB, vCC
        4, //AF: rem-double vAA, vBB, vCC
        2, //B0: add-int/2addr vA, vB
        2, //B1: sub-int/2addr vA, vB
        2, //B2: mul-int/2addr vA, vB
        2, //B3: div-int/2addr vA, vB
        2, //B4: rem-int/2addr vA, vB
        2, //B5: and-int/2addr vA, vB
        2, //B6: or-int/2addr vA, vB
        2, //B7: xor-int/2addr vA, vB
        2, //B8: shl-int/2addr vA, vB
        2, //B9: shr-int/2addr vA, vB
        2, //BA: ushr-int/2addr vA, vB
        2, //BB: add-long/2addr vA, vB
        2, //BC: sub-long/2addr vA, vB
        2, //BD: mul-long/2addr vA, vB
        2, //BE: div-long/2addr vA, vB
        2, //BF: rem-long/2addr vA, vB
        2, //C0: and-long/2addr vA, vB
        2, //C1: or-long/2addr vA, vB
        2, //C2: xor-long/2addr vA, vB
        2, //C3: shl-long/2addr vA, vB
        2, //C4: shr-long/2addr vA, vB
        2, //C5: ushr-long/2addr vA, vB
        2, //C6: add-float/2addr vA, vB
        2, //C7: sub-float/2addr vA, vB
        2, //C8: mul-float/2addr vA, vB
        2, //C9: div-float/2addr vA, vB
        2, //CA: rem-float/2addr vA, vB
        2, //CB: add-double/2addr vA, vB
        2, //CC: sub-double/2addr vA, vB
        2, //CD: mul-double/2addr vA, vB
        2, //CE: div-double/2addr vA, vB
        2, //CF: rem-double/2addr vA, vB
        4, //D0: add-int/lit16 vA, vB, #+CCCC
        4, //D1: rsub-int/lit16 vA, vB, #+CCCC
        4, //D2: mul-int/lit16 vA, vB, #+CCCC
        4, //D3: div-int/lit16 vA, vB, #+CCCC
        4, //D4: rem-int/lit16 vA, vB, #+CCCC
        4, //D5: and-int/lit16 vA, vB, #+CCCC
        4, //D6: or-int/lit16 vA, vB, #+CCCC
        4, //D7: xor-int/lit16 vA, vB, #+CCCC
        4, //D8: add-int/lit8 vAA, vBB, #+CC
        4, //D9: rsub-int/lit8 vAA, vBB, #+CC
        4, //DA: mul-int/lit8 vAA, vBB, #+CC
        4, //DB: div-int/lit8 vAA, vBB, #+CC
        4, //DC: rem-int/lit8 vAA, vBB, #+CC
        4, //DD: and-int/lit8 vAA, vBB, #+CC
        4, //DE: or-int/lit8 vAA, vBB, #+CC
        4, //DF: xor-int/lit8 vAA, vBB, #+CC
        4, //E0: shl-int/lit8 vAA, vBB, #+CC
        4, //E1: shr-int/lit8 vAA, vBB, #+CC
        4, //E2: ushr-int/lit8 vAA, vBB, #+CC
        2, //E3: unused
        2, //E4: unused
        2, //E5: unused
        2, //E6: unused
        2, //E7: unused
        2, //E8: unused
        2, //E9: unused
        2, //EA: unused
        2, //EB: unused
        2, //EC: unused
        2, //ED: unused
        2, //EE: unused
        2, //EF: unused
        2, //F0: unused
        2, //F1: unused
        2, //F2: unused
        2, //F3: unused
        2, //F4: unused
        2, //F5: unused
        2, //F6: unused
        2, //F7: unused
        2, //F8: unused
        2, //F9: unused
        8, //FA: invoke-polymorphic {vC, vD, vE, vF, vG}, meth@BBBB, proto@HHHH
        8, //FB: invoke-polymorphic/range {vCCCC .. vNNNN}, meth@BBBB, proto@HHHH
        6, //FC: invoke-custom {vC, vD, vE, vF, vG}, call_site@BBBB
        6, //FD: invoke-custom/range {vCCCC .. vNNNN}, call_site@BBBB
        4, //FE: const-method-handle vAA, method_handle@BBBB
        4, //FF: const-method-type vAA, proto@BBBB
};

unsigned long CDisassembler::length(unsigned char *bytecode) {
    if(isPayload(bytecode)) {
        return getPayloadSize(bytecode);
    }

    return instrLenMap[bytecode[0]];
}

bool CDisassembler::isPayload(unsigned char* bytecode) {
    unsigned short shortInstr = *( unsigned short* )bytecode;

    return shortInstr == 0x100 || shortInstr == 0x200 || shortInstr == 0x300;
}

unsigned short CDisassembler::getPayloadSize(unsigned char *bytecode) {
    unsigned short shortInstr = *( unsigned short* )bytecode;

    if( shortInstr == 0x100 ) {
        unsigned short size = *( unsigned short* )&bytecode[2];
        return 8 + (size * 4);
    } else if( shortInstr == 0x200 ) {
        unsigned short size = *( unsigned short* )&bytecode[2];
        return 4 + (size * 4) * 2;
    } else if( shortInstr == 0x300 ) {
        unsigned short elementWidth = *( unsigned short* )&bytecode[2];
        unsigned int size = *( unsigned int* )&bytecode[4];
        return ( 4 + (size * elementWidth + 1) / 2) * 2;
    }

    return 0;
}

bool CDisassembler::isInvocation(unsigned char *bytecode) {
    return (bytecode[0] >= 0x6E && bytecode[0] < 0x73) || (bytecode[0] >= 0x74 && bytecode[0] < 0x79);
}

unsigned short CDisassembler::getInvocationMethodId(unsigned char *bytecode) {
    return *( unsigned short* )( &bytecode[2] );
}
