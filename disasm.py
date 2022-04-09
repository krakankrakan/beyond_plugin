from binaryninja.function import InstructionTextToken
from binaryninja.enums import InstructionTextTokenType, BranchType

from enum import Enum

import beyond.utils as utils

# Opcodes are 4 bit long
OPCODE_LENGTH = 4

# Index positions in the opcode definitions
OPCODE_DEF_INDEX_OPCODE_NAME            = 0
OPCODE_DEF_INDEX_OPERANDS               = 1
OPCODE_DEF_INDEX_OPERAND_DEFINITIONS    = 2
OPCODE_DEF_INSTR_DEC_FLAGS              = 3
OPCODE_DEF_INDEX_OPCODE_MASK_0          = 4
OPCODE_DEF_INDEX_OPCODE_MASK_1          = 5
OPCODE_DEF_INDEX_OPERAND_MASKS          = 6

PREV_INSTRUCTION_ADDR                   = 0

class InstInfo(Enum):
    NONE = 0
    LSB = 1
    BRANCH = 2
    CALL = 3
    INDIRECT = 4
    CONDITIONAL_BRANCH = 5
    RETURN = 6
    UNSIGNED = 7

class Register(Enum):
    r0  = "r0"
    r1  = "r1"
    r2  = "r2"
    r3  = "r3"
    r4  = "r4"
    r5  = "r5"
    r6  = "r6"
    r7  = "r7"
    r8  = "r8"
    r9  = "r9"
    r10 = "r10"
    r11 = "r11"
    r12 = "r12"
    r13 = "r13"
    r14 = "r14"
    r15 = "r15"
    r16 = "r16"
    r17 = "r17"
    r18 = "r18"
    r19 = "r19"
    r20  = "r20"
    r21  = "r21"
    r22  = "r22"
    r23  = "r23"
    r24  = "r24"
    r25  = "r25"
    r26  = "r26"
    r27  = "r27"
    r28  = "r28"
    r29  = "r29"
    r30  = "r30"
    r31  = "r31"

class OperandType(Enum):
    Immediate = 0,
    Register = 1,
    Memory = 2

class Operand:
    def visit(self):
        return None

class RegisterOperand(Operand):
    register = None

    def __init__(self, register):
        self.register = register

    def __str__(self):
        return "<RegisterOperand register: %s>" % (self.register)

    def visit(self):
        result = []
        result.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, self.register.value))
        return result

class ImmediateOperand(Operand):
    immediate = 0

    def __init__(self, immediate):
        self.immediate = immediate

    def __str__(self):
        return "<ImmediateOperand immediate: %s>" % (self.immediate)

    def visit(self):
        result = []
        result.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, hex(self.immediate)))
        return result

class AddressOperand(Operand):
    address = 0

    def __init__(self, address):
        self.address = address

    def __str__(self):
        return "<AddressOperand address: %s>" % (self.address)

    def visit(self):
        result = []
        result.append(InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, hex(self.address)))
        return result

class MemoryOperand(Operand):
    def __init__(self, operands):
        self.operands = operands

    def __str__(self):
        return "<MemoryOperand operands: %s>" % (self.operands)

    def visit(self):
        result = []
        result.append(InstructionTextToken(InstructionTextTokenType.BeginMemoryOperandToken, "("))
        result.extend(self.operands.visit())
        result.append(InstructionTextToken(InstructionTextTokenType.EndMemoryOperandToken, ")"))
        return result

class Instruction():
    operands = []

    opcode = ""

    def __init__(self, opcode, operands):
        self.opcode = opcode
        self.operands = operands

    def __str__(self):
        s = "<Instruction opcode: %s, operands:" % (self.opcode)
        for operand in self.operands: s += " %s" % (operand)
        s += ">"
        return s

    # Get the disassembly of the instructions (using tokens)
    def get_instruction_text(self):
        result = []
        result.append(InstructionTextToken(InstructionTextTokenType.TextToken, self.opcode))
        result.extend(self.visit_operands())

        #print("get_instruction_text:")
        #print(result)

        return result

    # recursive determine instruction tokens from operands list
    def visit_operands(self):
        result = []

        if len(self.operands) > 0:
            result.append(InstructionTextToken(InstructionTextTokenType.TextToken, ' '))

        for operandIdx in range(0, len(self.operands)):
            result.extend(self.operands[operandIdx].visit())

            # If there is a next operand, add a separator
            if (operandIdx < len(self.operands) - 1):
                result.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ","))

        return result

# Used for automatically generating the instruction definitions.
# Definitions partially copied from patched binutils for the Beyond ISA.
beyond_opcodes = [
    ["bt.movi",	    "rD,G",		    "0x0 00 DD DDD0 GGGG", [InstInfo.NONE]],
    ["bt.addi",	    "rD,G",		    "0x0 00 DD DDD1 GGGG", [InstInfo.NONE]],
    ["bt.mov",	    "rD,rA",	    "0x0 01 DD DDDA AAAA", [InstInfo.NONE]],
    ["bt.add",	    "rD,rA",	    "0x0 10 DD DDDA AAAA", [InstInfo.NONE]],
    ["bt.j",	    "T",		    "0x0 11 TT TTTT TTTT", [InstInfo.LSB, InstInfo.BRANCH]],
    ["bn.sb",	    "N(rA),rB",	    "0x2 00 BB BBBA AAAA NNNN NNNN", [InstInfo.NONE]],
    ["bn.lbz",	    "rD,N(rA)",	    "0x2 01 DD DDDA AAAA NNNN NNNN", [InstInfo.NONE]],
    ["bn.sh",	    "M(rA),rB",	    "0x2 10 BB BBBA AAAA 0MMM MMMM", [InstInfo.NONE]],
    ["bn.lhz",	    "rD,M(rA)",	    "0x2 10 DD DDDA AAAA 1MMM MMMM", [InstInfo.NONE]],
    ["bn.sw",	    "K(rA),rB",	    "0x2 11 BB BBBA AAAA 00KK KKKK", [InstInfo.NONE]],
    ["bn.lwz",	    "rD,K(rA)",	    "0x2 11 DD DDDA AAAA 01KK KKKK", [InstInfo.NONE]],
    ["bn.lws",	    "rD,K(rA)",	    "0x2 11 DD DDDA AAAA 10KK KKKK", [InstInfo.NONE]],
    ["bn.sd",	    "J(rA),rB",	    "0x2 11 BB BBBA AAAA 110J JJJJ", [InstInfo.NONE]],
    ["bn.ld",	    "rD,J(rA)",	    "0x2 11 DD DDDA AAAA 111J JJJJ", [InstInfo.NONE]],
    ["bn.addi",	    "rD,rA,O",	    "0x3 00 DD DDDA AAAA OOOO OOOO", [InstInfo.NONE]],
    ["bn.andi",	    "rD,rA,N",	    "0x3 01 DD DDDA AAAA NNNN NNNN", [InstInfo.NONE]],
    ["bn.ori",	    "rD,rA,N",	    "0x3 10 DD DDDA AAAA NNNN NNNN", [InstInfo.NONE]],
    ["bn.sfeqi",	"rA,O",		    "0x3 11 00 000A AAAA OOOO OOOO", [InstInfo.NONE]],
    ["bn.sfnei",	"rA,O",		    "0x3 11 00 001A AAAA OOOO OOOO", [InstInfo.NONE]],
    ["bn.sfgesi",	"rA,O",		    "0x3 11 00 010A AAAA OOOO OOOO", [InstInfo.NONE]],
    ["bn.sfgeui",	"rA,O",		    "0x3 11 00 011A AAAA OOOO OOOO", [InstInfo.NONE]],
    ["bn.sfgtsi",	"rA,O",		    "0x3 11 00 100A AAAA OOOO OOOO", [InstInfo.NONE]],
    ["bn.sfgtui",	"rA,O",		    "0x3 11 00 101A AAAA OOOO OOOO", [InstInfo.NONE]],
    ["bn.sflesi",	"rA,O",		    "0x3 11 00 110A AAAA OOOO OOOO", [InstInfo.NONE]],
    ["bn.sfleui",	"rA,O",		    "0x3 11 00 111A AAAA OOOO OOOO", [InstInfo.NONE]],
    ["bn.sfltsi",	"rA,O",		    "0x3 11 01 000A AAAA OOOO OOOO", [InstInfo.NONE]],
    ["bn.sfltui",	"rA,O",		    "0x3 11 01 001A AAAA OOOO OOOO", [InstInfo.NONE]],
    ["bn.sfeq",	    "rA,rB",	    "0x3 11 01 010A AAAA BBBB B---", [InstInfo.NONE]],
    ["bn.sfne",	    "rA,rB",	    "0x3 11 01 011A AAAA BBBB B---", [InstInfo.NONE]],
    ["bn.sfges",	"rA,rB",	    "0x3 11 01 100A AAAA BBBB B---", [InstInfo.NONE]],
    ["bn.sfgeu",	"rA,rB",	    "0x3 11 01 101A AAAA BBBB B---", [InstInfo.NONE]],
    ["bn.sfgts",	"rA,rB",	    "0x3 11 01 110A AAAA BBBB B---", [InstInfo.NONE]],
    ["bn.sfgtu",	"rA,rB",	    "0x3 11 01 111A AAAA BBBB B---", [InstInfo.NONE]],
    ["bn.extbz",	"rD,rA",	    "0x3 11 10 -00A AAAA DDDD D000", [InstInfo.NONE]],
    ["bn.extbs",	"rD,rA",	    "0x3 11 10 -00A AAAA DDDD D001", [InstInfo.NONE]],
    ["bn.exthz",	"rD,rA",	    "0x3 11 10 -00A AAAA DDDD D010", [InstInfo.NONE]],
    ["bn.exths",	"rD,rA",	    "0x3 11 10 -00A AAAA DDDD D011", [InstInfo.NONE]],
    ["bn.ff1",	    "rD,rA",	    "0x3 11 10 -00A AAAA DDDD D100", [InstInfo.NONE]],
    ["bn.clz",	    "rD,rA",	    "0x3 11 10 -00A AAAA DDDD D101", [InstInfo.NONE]],
    ["bn.bitrev",	"rD,rA",	    "0x3 11 10 -00A AAAA DDDD D110", [InstInfo.NONE]],
    ["bn.swab",	    "rD,rA",	    "0x3 11 10 -00A AAAA DDDD D111", [InstInfo.NONE]],
    ["bn.mfspr",	"rD,rA",	    "0x3 11 10 -01A AAAA DDDD D000", [InstInfo.NONE]],
    ["bn.mtspr",	"rA,rB",	    "0x3 11 10 -01A AAAA BBBB B001", [InstInfo.NONE]],
    ["bn.abs",	    "rD,rA",	    "0x3 11 10 -10A AAAA DDDD D000", [InstInfo.NONE]],
    ["bn.sqr",	    "rD,rA",	    "0x3 11 10 -10A AAAA DDDD D001", [InstInfo.NONE]],
    ["bn.sqra",	    "rD,rA",	    "0x3 11 10 -10A AAAA DDDD D010", [InstInfo.NONE]],
    ["bn.casei",	"rA,N",		    "0x3 11 11 -00A AAAA NNNN NNNN", [InstInfo.NONE]],
    ["bn.beqi",	    "rB,E,P",	    "0x4 00 00 EEEB BBBB PPPP PPPP", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH]],
    ["bn.bnei",	    "rB,E,P",	    "0x4 00 01 EEEB BBBB PPPP PPPP", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH]],
    ["bn.bgesi",	"rB,E,P",	    "0x4 00 10 EEEB BBBB PPPP PPPP", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH]],
    ["bn.bgtsi",	"rB,E,P",	    "0x4 00 11 EEEB BBBB PPPP PPPP", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH]],
    ["bn.blesi",	"rB,E,P",	    "0x4 01 00 EEEB BBBB PPPP PPPP", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH]],
    ["bn.bltsi",	"rB,E,P",	    "0x4 01 01 EEEB BBBB PPPP PPPP", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH]],
    ["bn.j",	    "Z",		    "0x4 01 10 ZZZZ ZZZZ ZZZZ ZZZZ", [InstInfo.LSB, InstInfo.BRANCH]],
    ["bn.bf",	    "S",		    "0x4 01 11 0010 SSSS SSSS SSSS", [InstInfo.NONE]],
    ["bn.bnf",	    "S",		    "0x4 01 11 0011 SSSS SSSS SSSS", [InstInfo.NONE]],
    ["bn.bo",	    "S",		    "0x4 01 11 0100 SSSS SSSS SSSS", [InstInfo.NONE]],
    ["bn.bno",	    "S",		    "0x4 01 11 0101 SSSS SSSS SSSS", [InstInfo.NONE]],
    ["bn.bc",	    "S",		    "0x4 01 11 0110 SSSS SSSS SSSS", [InstInfo.NONE]],
    ["bn.bnc",	    "S",		    "0x4 01 11 0111 SSSS SSSS SSSS", [InstInfo.NONE]],
    ["bn.entri",	"F,N",		    "0x4 01 11 1010 FFFF NNNN NNNN", [InstInfo.NONE]],
    ["bn.reti",	    "F,N",		    "0x4 01 11 1011 FFFF NNNN NNNN", [InstInfo.NONE]],
    ["bn.rtnei",	"F,N",		    "0x4 01 11 1100 FFFF NNNN NNNN", [InstInfo.NONE]],
    ["bn.return",	"",		        "0x4 01 11 1101 --00 ---- ----", [InstInfo.NONE]],
    ["bn.jalr",	    "rA",		    "0x4 01 11 1101 --01 AAAA A---", [InstInfo.LSB, InstInfo.BRANCH]],
    ["bn.jr",	    "rA",		    "0x4 01 11 1101 --10 AAAA A---", [InstInfo.LSB, InstInfo.BRANCH]],
    ["bn.jal",	    "s",		    "0x4 10 ss ssss ssss ssss ssss", [InstInfo.LSB, InstInfo.BRANCH]],
    ["bn.mlwz",	    "rD,K(rA),C",	"0x5 00 DD DDDA AAAA CCKK KKKK", [InstInfo.NONE]],
    ["bn.msw",	    "K(rA),rB,C",	"0x5 01 BB BBBA AAAA CCKK KKKK", [InstInfo.NONE]],
    ["bn.mld",	    "rD,H(rA),C",	"0x5 10 DD DDDA AAAA CC0H HHHH", [InstInfo.NONE]],
    ["bn.msd",	    "H(rA),rB,C",	"0x5 10 BB BBBA AAAA CC1H HHHH", [InstInfo.NONE]],
    ["bn.lwza",	    "rD,rA,L",	    "0x5 11 DD DDDA AAAA 1100 LLLL", [InstInfo.NONE]],
    ["bn.swa",	    "rA,rB,L",	    "0x5 11 BB BBBA AAAA 1101 LLLL", [InstInfo.NONE]],
    ["bn.and",	    "rD,rA,rB",	    "0x6 00 DD DDDA AAAA BBBB B000", [InstInfo.NONE]],
    ["bn.or",	    "rD,rA,rB",	    "0x6 00 DD DDDA AAAA BBBB B001", [InstInfo.NONE]],
    ["bn.xor",	    "rD,rA,rB",	    "0x6 00 DD DDDA AAAA BBBB B010", [InstInfo.NONE]],
    ["bn.nand",	    "rD,rA,rB",	    "0x6 00 DD DDDA AAAA BBBB B011", [InstInfo.NONE]],
    ["bn.add",	    "rD,rA,rB",	    "0x6 00 DD DDDA AAAA BBBB B100", [InstInfo.NONE]],
    ["bn.sub",	    "rD,rA,rB",	    "0x6 00 DD DDDA AAAA BBBB B101", [InstInfo.NONE]],
    ["bn.sll",	    "rD,rA,rB",	    "0x6 00 DD DDDA AAAA BBBB B110", [InstInfo.NONE]],
    ["bn.srl",	    "rD,rA,rB",	    "0x6 00 DD DDDA AAAA BBBB B111", [InstInfo.NONE]],
    ["bn.sra",	    "rD,rA,rB",	    "0x6 01 DD DDDA AAAA BBBB B000", [InstInfo.NONE]],
    ["bn.ror",	    "rD,rA,rB",	    "0x6 01 DD DDDA AAAA BBBB B001", [InstInfo.NONE]],
    ["bn.cmov",	    "rD,rA,rB",	    "0x6 01 DD DDDA AAAA BBBB B010", [InstInfo.NONE]],
    ["bn.mul",	    "rD,rA,rB",	    "0x6 01 DD DDDA AAAA BBBB B011", [InstInfo.NONE]],
    ["bn.div",	    "rD,rA,rB",	    "0x6 01 DD DDDA AAAA BBBB B100", [InstInfo.NONE]],
    ["bn.divu",	    "rD,rA,rB",	    "0x6 01 DD DDDA AAAA BBBB B101", [InstInfo.NONE]],
    ["bn.mac",	    "rA,rB",	    "0x6 01 00 000A AAAA BBBB B110", [InstInfo.NONE]],
    ["bn.macs",	    "rA,rB",	    "0x6 01 00 001A AAAA BBBB B110", [InstInfo.NONE]],
    ["bn.macsu",	"rA,rB",	    "0x6 01 00 010A AAAA BBBB B110", [InstInfo.NONE]],
    ["bn.macuu",	"rA,rB",	    "0x6 01 00 011A AAAA BBBB B110", [InstInfo.NONE]],
    ["bn.smactt",	"rA,rB",	    "0x6 01 00 100A AAAA BBBB B110", [InstInfo.NONE]],
    ["bn.smacbb",	"rA,rB",	    "0x6 01 00 101A AAAA BBBB B110", [InstInfo.NONE]],
    ["bn.smactb",	"rA,rB",	    "0x6 01 00 110A AAAA BBBB B110", [InstInfo.NONE]],
    ["bn.umactt",	"rA,rB",	    "0x6 01 00 111A AAAA BBBB B110", [InstInfo.NONE]],
    ["bn.umacbb",	"rA,rB",	    "0x6 01 01 000A AAAA BBBB B110", [InstInfo.NONE]],
    ["bn.umactb",	"rA,rB",	    "0x6 01 01 001A AAAA BBBB B110", [InstInfo.NONE]],
    ["bn.msu",	    "rA,rB",	    "0x6 01 01 010A AAAA BBBB B110", [InstInfo.NONE]],
    ["bn.msus",	    "rA,rB",	    "0x6 01 01 011A AAAA BBBB B110", [InstInfo.NONE]],
    ["bn.addc",	    "rD,rA,rB",	    "0x6 01 DD DDDA AAAA BBBB B111", [InstInfo.NONE]],
    ["bn.subb",	    "rD,rA,rB",	    "0x6 10 DD DDDA AAAA BBBB B000", [InstInfo.NONE]],
    ["bn.flb",	    "rD,rA,rB",	    "0x6 10 DD DDDA AAAA BBBB B001", [InstInfo.NONE]],
    ["bn.mulhu",	"rD,rA,rB",	    "0x6 10 DD DDDA AAAA BBBB B010", [InstInfo.NONE]],
    ["bn.mulh",	    "rD,rA,rB",	    "0x6 10 DD DDDA AAAA BBBB B011", [InstInfo.NONE]],
    ["bn.mod",	    "rD,rA,rB",	    "0x6 10 DD DDDA AAAA BBBB B100", [InstInfo.NONE]],
    ["bn.modu",	    "rD,rA,rB",	    "0x6 10 DD DDDA AAAA BBBB B101", [InstInfo.NONE]],
    ["bn.aadd",	    "rD,rA,rB",	    "0x6 10 DD DDDA AAAA BBBB B110", [InstInfo.NONE]],
    ["bn.cmpxchg",	"rD,rA,rB",	    "0x6 10 DD DDDA AAAA BBBB B111", [InstInfo.NONE]],
    ["bn.slli",	    "rD,rA,H",	    "0x6 11 DD DDDA AAAA HHHH H-00", [InstInfo.NONE]],
    ["bn.srli",	    "rD,rA,H",	    "0x6 11 DD DDDA AAAA HHHH H-01", [InstInfo.NONE]],
    ["bn.srai",	    "rD,rA,H",	    "0x6 11 DD DDDA AAAA HHHH H-10", [InstInfo.NONE]],
    ["bn.rori",	    "rD,rA,H",	    "0x6 11 DD DDDA AAAA HHHH H-11", [InstInfo.NONE]],
    ["fn.add.s",	"rD,rA,rB",	    "0x7 00 DD DDDA AAAA BBBB B000", [InstInfo.NONE]],
    ["fn.sub.s",	"rD,rA,rB",	    "0x7 00 DD DDDA AAAA BBBB B001", [InstInfo.NONE]],
    ["fn.mul.s",	"rD,rA,rB",	    "0x7 00 DD DDDA AAAA BBBB B010", [InstInfo.NONE]],
    ["fn.div.s",	"rD,rA,rB",	    "0x7 00 DD DDDA AAAA BBBB B011", [InstInfo.NONE]],
    ["bn.adds",	    "rD,rA,rB",	    "0x7 01 DD DDDA AAAA BBBB B000", [InstInfo.NONE]],
    ["bn.subs",	    "rD,rA,rB",	    "0x7 01 DD DDDA AAAA BBBB B001", [InstInfo.NONE]],
    ["bn.xaadd",	"rD,rA,rB",	    "0x7 01 DD DDDA AAAA BBBB B010", [InstInfo.NONE]],
    ["bn.xcmpxchg", "rD,rA,rB",	    "0x7 01 DD DDDA AAAA BBBB B011", [InstInfo.NONE]],
    ["bn.max",	    "rD,rA,rB",	    "0x7 01 DD DDDA AAAA BBBB B100", [InstInfo.NONE]],
    ["bn.min",	    "rD,rA,rB",	    "0x7 01 DD DDDA AAAA BBBB B101", [InstInfo.NONE]],
    ["bn.lim",	    "rD,rA,rB",	    "0x7 01 DD DDDA AAAA BBBB B110", [InstInfo.NONE]],
    ["bn.slls",	    "rD,rA,rB",	    "0x7 10 DD DDDA AAAA BBBB B-00", [InstInfo.NONE]],
    ["bn.sllis",	"rD,rA,H",	    "0x7 10 DD DDDA AAAA HHHH H-01", [InstInfo.NONE]],
    ["fn.ftoi.s",	"rD,rA",	    "0x7 11 10 --0A AAAA DDDD D000", [InstInfo.NONE]],
    ["fn.itof.s",	"rD,rA",	    "0x7 11 10 --0A AAAA DDDD D001", [InstInfo.NONE]],
    ["bw.sb",	    "h(rA),rB",	    "0x8 00 BB BBBA AAAA hhhh hhhh hhhh hhhh hhhh hhhh hhhh hhhh", [InstInfo.NONE]],
    ["bw.lbz",	    "rD,h(rA)",	    "0x8 01 DD DDDA AAAA hhhh hhhh hhhh hhhh hhhh hhhh hhhh hhhh", [InstInfo.NONE]],
    ["bw.sh",	    "i(rA),rB",	    "0x8 10 BB BBBA AAAA 0iii iiii iiii iiii iiii iiii iiii iiii", [InstInfo.NONE]],
    ["bw.lhz",	    "rD,i(rA)",	    "0x8 10 DD DDDA AAAA 1iii iiii iiii iiii iiii iiii iiii iiii", [InstInfo.NONE]],
    ["bw.sw",	    "w(rA),rB",	    "0x8 11 BB BBBA AAAA 00ww wwww wwww wwww wwww wwww wwww wwww", [InstInfo.NONE]],
    ["bw.lwz",	    "rD,w(rA)",	    "0x8 11 DD DDDA AAAA 01ww wwww wwww wwww wwww wwww wwww wwww", [InstInfo.NONE]],
    ["bw.lws",	    "rD,w(rA)",	    "0x8 11 DD DDDA AAAA 10ww wwww wwww wwww wwww wwww wwww wwww", [InstInfo.NONE]],
    ["bw.sd",	    "v(rA),rB",	    "0x8 11 BB BBBA AAAA 110v vvvv vvvv vvvv vvvv vvvv vvvv vvvv", [InstInfo.NONE]],
    ["bw.ld",	    "rD,v(rA)",	    "0x8 11 DD DDDA AAAA 111v vvvv vvvv vvvv vvvv vvvv vvvv vvvv", [InstInfo.NONE]],
    ["bw.addi",	    "rD,rA,g",	    "0x9 00 DD DDDA AAAA gggg gggg gggg gggg gggg gggg gggg gggg", [InstInfo.NONE]],
    ["bw.andi",	    "rD,rA,h",	    "0x9 01 DD DDDA AAAA hhhh hhhh hhhh hhhh hhhh hhhh hhhh hhhh", [InstInfo.NONE]],
    ["bw.ori",	    "rD,rA,h",	    "0x9 10 DD DDDA AAAA hhhh hhhh hhhh hhhh hhhh hhhh hhhh hhhh", [InstInfo.NONE]],
    ["bw.sfeqi",	"rA,g",		    "0x9 11 01 10-A AAAA gggg gggg gggg gggg gggg gggg gggg gggg", [InstInfo.NONE]],
    ["bw.sfnei",	"rA,g",		    "0x9 11 01 11-A AAAA gggg gggg gggg gggg gggg gggg gggg gggg", [InstInfo.NONE]],
    ["bw.sfgesi",	"rA,g",		    "0x9 11 10 00-A AAAA gggg gggg gggg gggg gggg gggg gggg gggg", [InstInfo.NONE]],
    ["bw.sfgeui",	"rA,g",		    "0x9 11 10 01-A AAAA gggg gggg gggg gggg gggg gggg gggg gggg", [InstInfo.NONE]],
    ["bw.sfgtsi",	"rA,g",		    "0x9 11 10 10-A AAAA gggg gggg gggg gggg gggg gggg gggg gggg", [InstInfo.NONE]],
    ["bw.sfgtui",	"rA,g",		    "0x9 11 10 11-A AAAA gggg gggg gggg gggg gggg gggg gggg gggg", [InstInfo.NONE]],
    ["bw.sflesi",	"rA,g",		    "0x9 11 11 00-A AAAA gggg gggg gggg gggg gggg gggg gggg gggg", [InstInfo.NONE]],
    ["bw.sfleui",	"rA,g",		    "0x9 11 11 01-A AAAA gggg gggg gggg gggg gggg gggg gggg gggg", [InstInfo.NONE]],
    ["bw.sfltsi",	"rA,g",		    "0x9 11 11 10-A AAAA gggg gggg gggg gggg gggg gggg gggg gggg", [InstInfo.NONE]],
    ["bw.sfltui",	"rA,g",		    "0x9 11 11 11-A AAAA gggg gggg gggg gggg gggg gggg gggg gggg", [InstInfo.NONE]],
    ["bw.beqi",	    "rB,I,u",	    "0xa 00 00 00II IIIB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH]],
    ["bw.bnei",	    "rB,I,u",	    "0xa 00 00 01II IIIB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH]],
    ["bw.bgesi",	"rB,I,u",	    "0xa 00 00 10II IIIB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH]],
    ["bw.bgtsi",	"rB,I,u",	    "0xa 00 00 11II IIIB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH]],
    ["bw.blesi",	"rB,I,u",	    "0xa 00 01 00II IIIB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH]],
    ["bw.bltsi",	"rB,I,u",	    "0xa 00 01 01II IIIB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH]],
    ["bw.bgeui",	"rB,I,u",	    "0xa 00 01 10II IIIB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH]],
    ["bw.bgtui",	"rB,I,u",	    "0xa 00 01 11II IIIB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH]],
    ["bw.bleui",	"rB,I,u",	    "0xa 00 10 00II IIIB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH]],
    ["bw.bltui",	"rB,I,u",	    "0xa 00 10 01II IIIB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH]],
    ["bw.beq",	    "rA,rB,u",	    "0xa 00 10 10AA AAAB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH]],
    ["bw.bne",	    "rA,rB,u",	    "0xa 00 10 11AA AAAB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH]],
    ["bw.bges",	    "rA,rB,u",	    "0xa 00 11 00AA AAAB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH]],
    ["bw.bgts",	    "rA,rB,u",	    "0xa 00 11 01AA AAAB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH]],
    ["bw.bgeu",	    "rA,rB,u",	    "0xa 00 11 10AA AAAB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH]],
    ["bw.bgtu",	    "rA,rB,u",	    "0xa 00 11 11AA AAAB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH]],
    ["bw.jal",	    "z",		    "0xa 01 00 00-- ---- zzzz zzzz zzzz zzzz zzzz zzzz zzzz zzzz", [InstInfo.LSB, InstInfo.CALL]],
    ["bw.j",	    "z",		    "0xa 01 00 01-- ---- zzzz zzzz zzzz zzzz zzzz zzzz zzzz zzzz", [InstInfo.LSB, InstInfo.BRANCH]],
    ["bw.bf",	    "z",		    "0xa 01 00 10-- ---- zzzz zzzz zzzz zzzz zzzz zzzz zzzz zzzz", [InstInfo.NONE]],
    ["bw.bnf",	    "z",		    "0xa 01 00 11-- ---- zzzz zzzz zzzz zzzz zzzz zzzz zzzz zzzz", [InstInfo.NONE]],
    ["bw.ja",	    "g",		    "0xa 01 01 00-- ---- gggg gggg gggg gggg gggg gggg gggg gggg", [InstInfo.NONE]],
    ["bw.jma",	    "rD,z",		    "0xa 01 01 01DD DDD0 zzzz zzzz zzzz zzzz zzzz zzzz zzzz zzzz", [InstInfo.NONE]],
    ["bw.jmal",	    "rD,z",		    "0xa 01 01 01DD DDD1 zzzz zzzz zzzz zzzz zzzz zzzz zzzz zzzz", [InstInfo.NONE]],
    ["bw.lma",	    "rD,z",		    "0xa 01 01 10DD DDD0 zzzz zzzz zzzz zzzz zzzz zzzz zzzz zzzz", [InstInfo.NONE]],
    ["bw.sma",	    "rB,z",		    "0xa 01 01 10BB BBB1 zzzz zzzz zzzz zzzz zzzz zzzz zzzz zzzz", [InstInfo.NONE]],
    ["bw.casewi",	"rB,z",		    "0xa 01 01 11BB BBB0 zzzz zzzz zzzz zzzz zzzz zzzz zzzz zzzz", [InstInfo.NONE]],
    ["fw.beq.s",	"rA,rB,u",	    "0xa 01 10 00AA AAAB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu", [InstInfo.NONE]],
    ["fw.bne.s",	"rA,rB,u",	    "0xa 01 10 01AA AAAB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu", [InstInfo.NONE]],
    ["fw.bge.s",	"rA,rB,u",	    "0xa 01 10 10AA AAAB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu", [InstInfo.NONE]],
    ["fw.bgt.s",	"rA,rB,u",	    "0xa 01 10 11AA AAAB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu", [InstInfo.NONE]],
    ["bw.mfspr",	"rD,rA,o",	    "0xa 10 DD DDDA AAAA oooo oooo oooo oooo oooo oooo ---- -000", [InstInfo.NONE]],
    ["bw.mtspr",	"rA,rB,o",	    "0xa 10 BB BBBA AAAA oooo oooo oooo oooo oooo oooo ---- -001", [InstInfo.NONE]],
    ["bw.addci",	"rD,rA,p",	    "0xa 10 DD DDDA AAAA pppp pppp pppp pppp pppp pppp ---- -010", [InstInfo.NONE]],
    ["bw.divi",	    "rD,rA,p",	    "0xa 10 DD DDDA AAAA pppp pppp pppp pppp pppp pppp ---- -011", [InstInfo.NONE]],
    ["bw.divui",	"rD,rA,o",	    "0xa 10 DD DDDA AAAA oooo oooo oooo oooo oooo oooo ---- -100", [InstInfo.NONE]],
    ["bw.muli",	    "rD,rA,p",	    "0xa 10 DD DDDA AAAA pppp pppp pppp pppp pppp pppp ---- -101", [InstInfo.NONE]],
    ["bw.xori",	    "rD,rA,p",	    "0xa 10 DD DDDA AAAA pppp pppp pppp pppp pppp pppp ---- -110", [InstInfo.NONE]],
    ["bw.mulas",	"rD,rA,rB,H",	"0xa 11 DD DDDA AAAA BBBB BHHH HH-- ---- ---- ---- --00 0000", [InstInfo.NONE]],
    ["bw.muluas",	"rD,rA,rB,H",	"0xa 11 DD DDDA AAAA BBBB BHHH HH-- ---- ---- ---- --00 0001", [InstInfo.NONE]],
    ["bw.mulras",	"rD,rA,rB,H",	"0xa 11 DD DDDA AAAA BBBB BHHH HH-- ---- ---- ---- --00 0010", [InstInfo.NONE]],
    ["bw.muluras",	"rD,rA,rB,H",	"0xa 11 DD DDDA AAAA BBBB BHHH HH-- ---- ---- ---- --00 0011", [InstInfo.NONE]],
    ["bw.mulsu",	"rD,rA,rB",	    "0xa 11 DD DDDA AAAA BBBB B--- ---- ---- ---- ---- --00 0100", [InstInfo.NONE]],
    ["bw.mulhsu",	"rD,rA,rB",	    "0xa 11 DD DDDA AAAA BBBB B--- ---- ---- ---- ---- --00 0101", [InstInfo.NONE]],
    ["bw.mulhlsu",	"rD,rQ,rA,rB",	"0xa 11 DD DDDA AAAA BBBB BQQQ QQ-- ---- ---- ---- --00 0110", [InstInfo.NONE]],       
    ["bw.smultt",	"rD,rA,rB",	    "0xa 11 DD DDDA AAAA BBBB B--- ---- ---- ---- ---- --10 0000", [InstInfo.NONE]],
    ["bw.smultb",	"rD,rA,rB",	    "0xa 11 DD DDDA AAAA BBBB B--- ---- ---- ---- ---- --10 0001", [InstInfo.NONE]],
    ["bw.smulbb",	"rD,rA,rB",	    "0xa 11 DD DDDA AAAA BBBB B--- ---- ---- ---- ---- --10 0010", [InstInfo.NONE]],
    ["bw.smulwb",	"rD,rA,rB",	    "0xa 11 DD DDDA AAAA BBBB B--- ---- ---- ---- ---- --10 0011", [InstInfo.NONE]],
    ["bw.smulwt",	"rD,rA,rB",	    "0xa 11 DD DDDA AAAA BBBB B--- ---- ---- ---- ---- --10 0100", [InstInfo.NONE]],
    ["bw.umultt",	"rD,rA,rB",	    "0xa 11 DD DDDA AAAA BBBB B--- ---- ---- ---- ---- --10 1000", [InstInfo.NONE]],
    ["bw.umultb",	"rD,rA,rB",	    "0xa 11 DD DDDA AAAA BBBB B--- ---- ---- ---- ---- --10 1001", [InstInfo.NONE]],
    ["bw.umulbb",	"rD,rA,rB",	    "0xa 11 DD DDDA AAAA BBBB B--- ---- ---- ---- ---- --10 1010", [InstInfo.NONE]],
    ["bw.umulwb",	"rD,rA,rB",	    "0xa 11 DD DDDA AAAA BBBB B--- ---- ---- ---- ---- --10 1011", [InstInfo.NONE]],
    ["bw.umulwt",	"rD,rA,rB",	    "0xa 11 DD DDDA AAAA BBBB B--- ---- ---- ---- ---- --10 1100", [InstInfo.NONE]],
    ["bw.smadtt",	"rD,rA,rB,rR",	"0xa 11 DD DDDA AAAA BBBB BRRR RR-- ---- ---- ---- --11 0000", [InstInfo.NONE]],
    ["bw.smadtb",	"rD,rA,rB,rR",	"0xa 11 DD DDDA AAAA BBBB BRRR RR-- ---- ---- ---- --11 0001", [InstInfo.NONE]],
    ["bw.smadbb",	"rD,rA,rB,rR",	"0xa 11 DD DDDA AAAA BBBB BRRR RR-- ---- ---- ---- --11 0010", [InstInfo.NONE]],
    ["bw.smadwb",	"rD,rA,rB,rR",	"0xa 11 DD DDDA AAAA BBBB BRRR RR-- ---- ---- ---- --11 0011", [InstInfo.NONE]],
    ["bw.smadwt",	"rD,rA,rB,rR",	"0xa 11 DD DDDA AAAA BBBB BRRR RR-- ---- ---- ---- --11 0100", [InstInfo.NONE]],
    ["bw.umadtt",	"rD,rA,rB,rR",	"0xa 11 DD DDDA AAAA BBBB BRRR RR-- ---- ---- ---- --11 1000", [InstInfo.NONE]],
    ["bw.umadtb",	"rD,rA,rB,rR",	"0xa 11 DD DDDA AAAA BBBB BRRR RR-- ---- ---- ---- --11 1001", [InstInfo.NONE]],
    ["bw.umadbb",	"rD,rA,rB,rR",	"0xa 11 DD DDDA AAAA BBBB BRRR RR-- ---- ---- ---- --11 1010", [InstInfo.NONE]],
    ["bw.umadwb",	"rD,rA,rB,rR",	"0xa 11 DD DDDA AAAA BBBB BRRR RR-- ---- ---- ---- --11 1011", [InstInfo.NONE]],
    ["bw.umadwt",	"rD,rA,rB,rR",	"0xa 11 DD DDDA AAAA BBBB BRRR RR-- ---- ---- ---- --11 1100", [InstInfo.NONE]],
    ["bw.copdss",	"rD,rA,rB,y",	"0xb 00 DD DDDA AAAA BBBB Byyy yyyy yyyy yyyy yyyy yyyy yyyy", [InstInfo.NONE]],
    ["bw.copd",	    "rD,g,H",	    "0xb 01 DD DDDH HHHH gggg gggg gggg gggg gggg gggg gggg gggg", [InstInfo.NONE]],
    ["bw.cop",	    "g,x",		    "0xb 10 xx xxxx xxxx gggg gggg gggg gggg gggg gggg gggg gggg", [InstInfo.NONE]],
    ["bg.sb",	    "Y(rA),rB",	    "0xc 00 BB BBBA AAAA YYYY YYYY YYYY YYYY", [InstInfo.NONE]],
    ["bg.lbz",	    "rD,Y(rA)",	    "0xc 01 DD DDDA AAAA YYYY YYYY YYYY YYYY", [InstInfo.NONE]],
    ["bg.sh",	    "X(rA),rB",	    "0xc 10 BB BBBA AAAA 0XXX XXXX XXXX XXXX", [InstInfo.NONE]],
    ["bg.lhz",	    "rD,X(rA)",	    "0xc 10 DD DDDA AAAA 1XXX XXXX XXXX XXXX", [InstInfo.NONE]],
    ["bg.sw",	    "W(rA),rB",	    "0xc 11 BB BBBA AAAA 00WW WWWW WWWW WWWW", [InstInfo.NONE]],
    ["bg.lwz",	    "rD,W(rA)",	    "0xc 11 DD DDDA AAAA 01WW WWWW WWWW WWWW", [InstInfo.NONE]],
    ["bg.lws",	    "rD,W(rA)",	    "0xc 11 DD DDDA AAAA 10WW WWWW WWWW WWWW", [InstInfo.NONE]],
    ["bg.sd",	    "V(rA),rB",	    "0xc 11 BB BBBA AAAA 110V VVVV VVVV VVVV", [InstInfo.NONE]],
    ["bg.ld",	    "rD,V(rA)",	    "0xc 11 DD DDDA AAAA 111V VVVV VVVV VVVV", [InstInfo.NONE]],
    ["bg.beqi",	    "rB,I,U",	    "0xd 00 00 00II IIIB BBBB UUUU UUUU UUUU", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH]],
    ["bg.bnei",	    "rB,I,U",	    "0xd 00 00 01II IIIB BBBB UUUU UUUU UUUU", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH]],
    ["bg.bgesi",	"rB,I,U",	    "0xd 00 00 10II IIIB BBBB UUUU UUUU UUUU", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH]],
    ["bg.bgtsi",	"rB,I,U",	    "0xd 00 00 11II IIIB BBBB UUUU UUUU UUUU", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH]],
    ["bg.blesi",	"rB,I,U",	    "0xd 00 01 00II IIIB BBBB UUUU UUUU UUUU", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH]],
    ["bg.bltsi",	"rB,I,U",	    "0xd 00 01 01II IIIB BBBB UUUU UUUU UUUU", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH]],
    ["bg.bgeui",	"rB,I,U",	    "0xd 00 01 10II IIIB BBBB UUUU UUUU UUUU", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH]],
    ["bg.bgtui",	"rB,I,U",	    "0xd 00 01 11II IIIB BBBB UUUU UUUU UUUU", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH]],
    ["bg.bleui",	"rB,I,U",	    "0xd 00 10 00II IIIB BBBB UUUU UUUU UUUU", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH]],
    ["bg.bltui",	"rB,I,U",	    "0xd 00 10 01II IIIB BBBB UUUU UUUU UUUU", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH]],
    ["bg.beq",	    "rA,rB,U",	    "0xd 00 10 10AA AAAB BBBB UUUU UUUU UUUU", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH]],
    ["bg.bne",	    "rA,rB,U",	    "0xd 00 10 11AA AAAB BBBB UUUU UUUU UUUU", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH]],
    ["bg.bges",	    "rA,rB,U",	    "0xd 00 11 00AA AAAB BBBB UUUU UUUU UUUU", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH]],
    ["bg.bgts",	    "rA,rB,U",	    "0xd 00 11 01AA AAAB BBBB UUUU UUUU UUUU", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH]],
    ["bg.bgeu",	    "rA,rB,U",	    "0xd 00 11 10AA AAAB BBBB UUUU UUUU UUUU", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH]],
    ["bg.bgtu",	    "rA,rB,U",	    "0xd 00 11 11AA AAAB BBBB UUUU UUUU UUUU", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH]],
    ["bg.jal",	    "t",		    "0xd 01 00 tttt tttt tttt tttt tttt tttt", [InstInfo.LSB, InstInfo.CALL]],
    ["bg.j",	    "t",		    "0xd 01 01 tttt tttt tttt tttt tttt tttt", [InstInfo.LSB, InstInfo.BRANCH]],
    ["bg.bf",	    "t",		    "0xd 01 10 tttt tttt tttt tttt tttt tttt", [InstInfo.LSB]],
    ["bg.bnf",	    "t",		    "0xd 01 11 tttt tttt tttt tttt tttt tttt", [InstInfo.LSB]],
    ["bg.addi",	    "rD,rA,Y",	    "0xd 10 DD DDDA AAAA YYYY YYYY YYYY YYYY", [InstInfo.NONE]],
    ["fg.beq.s",	"rA,rB,U",	    "0xd 11 00 00AA AAAB BBBB UUUU UUUU UUUU", [InstInfo.NONE]],
    ["fg.bne.s",	"rA,rB,U",	    "0xd 11 00 01AA AAAB BBBB UUUU UUUU UUUU", [InstInfo.NONE]],
    ["fg.bge.s",	"rA,rB,U",	    "0xd 11 00 10AA AAAB BBBB UUUU UUUU UUUU", [InstInfo.NONE]],
    ["fg.bgt.s",	"rA,rB,U",	    "0xd 11 00 11AA AAAB BBBB UUUU UUUU UUUU", [InstInfo.NONE]]
]

# Extract the immediate from an instruction given the instruction and the mask
def extract_immediate(instruction, mask, lsb_first, unsigned):
    shift         = utils.get_first_one_pos(mask)
    immediate = 0

    #print("Extract immediate")
    #print(instruction)
    #print(mask)
    #print(shift)

    immediate = (instruction & mask) >> shift
    immediate_size = utils.get_last_one_pos(mask) - shift + 1

    if lsb_first:
        immediate = utils.reverse_bits(immediate, immediate_size)
    
    if not unsigned:
        immediate = utils.get_signed_num(immediate, immediate_size)

    return immediate

# Extract the register from an instruction given the instruction and the mask
def extract_register(instruction, mask):
    register_number = extract_immediate(instruction, mask, False, True)

    return Register("r" + str(register_number))

# Takes an operand definition and returns a bitmask for the immediate. 
# Exmple:
# opernad = "G", instuction_definition = "00 00 DD DDD0 GGGG", return = "00 00 00 0000 GGGG"
def parse_immediate(operand, instruction_definition):
    ret_immediate_mask = ""

    # Get the character that identifies the immediate
    immediate_identifier = operand[0]

    # Extract a mask for the immediate
    immediate_mask = instruction_definition
    for i in range(0, len(instruction_definition)): 
        if immediate_mask[i] != immediate_identifier:
            ret_immediate_mask += "0"
        else:
            ret_immediate_mask += "1"

    return int(ret_immediate_mask, 2)

def parse_register(operand, instruction_definition):
    ret_register_mask = ""

    # Get the character that identifies the register
    register_identifier = operand[1]

    # Extract a mask for the register
    register_mask = instruction_definition
    for i in range(0, len(instruction_definition)): 
        if register_mask[i] != register_identifier:
            ret_register_mask += "0"
        else:
            ret_register_mask += "1"

    return int(ret_register_mask, 2)

def parse_opcode(instruction_definition):
    ret_opcode_mask_0 = ""
    ret_opcode_mask_1 = ""

    # Extract a mask for the 0s of the opcode
    opcode_mask = instruction_definition
    for i in range(0, len(instruction_definition)): 
        if opcode_mask[i] == "0":
            ret_opcode_mask_0 += "1"
        else:
            ret_opcode_mask_0 += "0"

    # Extract a mask for the 1s of the opcode
    for i in range(0, len(instruction_definition)): 
        if opcode_mask[i] == "1":
            ret_opcode_mask_1 += "1"
        else:
            ret_opcode_mask_1 += "0"

    return int(ret_opcode_mask_0, 2), int(ret_opcode_mask_1, 2)

def parse_operand(operand, instruction_definition):
    if len(operand) < 1:
        return None

    # Immediate
    if len(operand) == 1:
        immediate_mask = parse_immediate(operand, instruction_definition)
        #print("Immediate mask: " + bin(immediate_mask))
        return (OperandType.Immediate, [immediate_mask])

    # Check for register
    if operand[0] == "r":
        register_mask = parse_register(operand, instruction_definition)
        #print("Register mask: " + bin(register_mask))
        return (OperandType.Register, [register_mask])

    # Memory access
    else:
        # Immediate
        immediate_mask = parse_immediate(operand, instruction_definition)

        # Register
        register_mask = parse_register(operand[2:-1], instruction_definition)
        return (OperandType.Memory, [register_mask, immediate_mask])

# Disassemble instructions.
# Return an instruction text 
def disassemble(data, addr):
    #print("Data: " + str(data))

    instruction      = None
    instruction_len  = 0
    instruction_data = None
    instr_dec_flags  = None
    found            = False

    #return None, 0, instruction_data

    # Limit input to 6 bytes
    #data = data[:6]
    #data_int = int.from_bytes(data, byteorder="little")

    if len(data) < 2:
        return None, 0, instruction_data

    for tested_instruction_len in range(2, 7):
        data_tmp = data[:tested_instruction_len]
        data_int = int.from_bytes(data_tmp, byteorder="big")

        print("addr: " + hex(addr) + " data_int: " + hex(data_int) + " bin: " + bin(data_int))

        for i in range(0, len(beyond_opcodes)):
            instructionOperands     = []

            operand_name            = beyond_opcodes[i][OPCODE_DEF_INDEX_OPCODE_NAME]
            instruction_definition  = beyond_opcodes[i][OPCODE_DEF_INDEX_OPERAND_DEFINITIONS]
            instr_dec_flags         = beyond_opcodes[i][OPCODE_DEF_INSTR_DEC_FLAGS]
            opcode_mask_0           = beyond_opcodes[i][OPCODE_DEF_INDEX_OPCODE_MASK_0]
            opcode_mask_1           = beyond_opcodes[i][OPCODE_DEF_INDEX_OPCODE_MASK_1]
            opcodes                 = beyond_opcodes[i][OPCODE_DEF_INDEX_OPERAND_MASKS:]

            # Test if instruction len matches
            #print(len(instruction_definition))
            #print(instruction_definition)
            if len(instruction_definition) != tested_instruction_len * 8:
                continue

            # Check if the opcode matches
            #if len(data)*8 != len(instruction_definition):
            #    continue
            
            # Check 0s
            if not ((~data_int & opcode_mask_0) == opcode_mask_0):
                continue
            # Check 1s
            if not ((data_int & opcode_mask_1) == opcode_mask_1):
                continue

            print("Disassemling for instruction: " + operand_name)
            print(instruction_definition)

            #for opcode in opcodes:
                #print(opcode)

            # Iterate over all opcodes
            for opcode in opcodes:
                #break
                if opcode[0] == OperandType.Immediate:
                    immediate_mask = opcode[1][0]

                    print("Immediate mask")
                    print(bin(immediate_mask))

                    immediate = extract_immediate(data_int, immediate_mask, InstInfo.LSB in instr_dec_flags, InstInfo.UNSIGNED in instr_dec_flags)

                    if InstInfo.BRANCH in instr_dec_flags or InstInfo.CALL in instr_dec_flags:
                        immediate = immediate + addr

                    instructionOperands.append(ImmediateOperand(immediate))
                break
                if opcode[0] == OperandType.Register:
                    register_mask = opcode[1][0]     

                    print("Register mask")
                    print(bin(register_mask))
                    print(type(register_mask))

                    register = extract_register(data_int, register_mask)

                    instructionOperands.append(RegisterOperand(register))
                if opcode[0] == OperandType.Memory:
                    register_mask  = opcode[1][0]
                    immediate_mask = opcode[1][1]

                    immediate = extract_immediate(data_int, immediate_mask, InstInfo.LSB in instr_dec_flags, InstInfo.UNSIGNED in instr_dec_flags)
                    register = extract_register(data_int, register_mask)

                    instructionOperands.append(MemoryOperand([ImmediateOperand(immediate), RegisterOperand(register)]))

            print("Parsed instruction operands: ")
            for op in instructionOperands:
                print(str(op))

            instruction_len = tested_instruction_len
            instruction = Instruction(operand_name, instructionOperands)

            print(str(instruction))

            found = True
            break

        if found:
            break

    if instruction == None:
        return None, 0, instruction_data

    #print(instruction)

    if InstInfo.BRANCH in instr_dec_flags:
        if len(instruction.operands) > 0:
            instruction_data = [BranchType.UnconditionalBranch, instruction.operands[0].immediate]

    if InstInfo.CALL in instr_dec_flags:
        if len(instruction.operands) > 0:
            instruction_data = [BranchType.CallDestination, instruction.operands[0].immediate]

    if InstInfo.INDIRECT in instr_dec_flags:
        if len(instruction.operands) > 0:
            instruction_data = [BranchType.IndirectBranch, instruction.operands[0].immediate]
    
    if InstInfo.RETURN in instr_dec_flags:
        if len(instruction.operands) > 0:
            instruction_data = [BranchType.FunctionReturn, instruction.operands[0].immediate]
    
    if InstInfo.CONDITIONAL_BRANCH in instr_dec_flags:
        if len(instruction.operands) > 0:
            instruction_data = [BranchType.TrueBranch, instruction.operands[-1].immediate, BranchType.FalseBranch, addr + instruction_len]

#    if instruction.opcode == "bt.j":
#        instruction_data = [BranchType.UnconditionalBranch, instruction.operands[0].immediate + addr]
#
#    if instruction.opcode == "bn.j":
#        instruction_data = [BranchType.UnconditionalBranch, instruction.operands[0].immediate + addr]
#
#    if instruction.opcode == "bn.bf":
#        instruction_data = [BranchType.UnconditionalBranch, instruction.operands[0].immediate + addr]
#
#    if instruction.opcode == "bn.bnf":
#        instruction_data = [BranchType.UnconditionalBranch, instruction.operands[0].immediate + addr]
#
#    if instruction.opcode == "bn.bo":
#        instruction_data = [BranchType.UnconditionalBranch, instruction.operands[0].immediate + addr]
#    
#    if instruction.opcode == "bn.bno":
#        instruction_data = [BranchType.UnconditionalBranch, instruction.operands[0].immediate + addr]
#
#    if instruction.opcode == "bn.bc":
#        instruction_data = [BranchType.UnconditionalBranch, instruction.operands[0].immediate + addr]
#
#    if instruction.opcode == "bn.bnc":
#        instruction_data = [BranchType.UnconditionalBranch, instruction.operands[0].immediate + addr]
#
#    if instruction.opcode == "bn.jalr":
#        instruction_data = [BranchType.IndirectBranch, instruction.operands[0].immediate + addr]
#
#    if instruction.opcode == "bn.jr":
#        instruction_data = [BranchType.IndirectBranch, instruction.operands[0].immediate + addr]
#
#    if instruction.opcode == "bn.jal":
#        instruction_data = [BranchType.CallDestination, instruction.operands[0].immediate + addr]
#
#    if instruction.opcode == "bw.jal":
#        instruction_data = [BranchType.CallDestination, instruction.operands[0].immediate + addr]
#
#    if instruction.opcode == "bw.j":
#        instruction_data = [BranchType.UnconditionalBranch, instruction.operands[0].immediate + addr]
#
#    if instruction.opcode == "bw.bf":
#        instruction_data = [BranchType.UnconditionalBranch, instruction.operands[0].immediate + addr]
#
#    if instruction.opcode == "bw.bnf":
#        instruction_data = [BranchType.UnconditionalBranch, instruction.operands[0].immediate + addr]
#
#    #if instruction.opcode == "bw.ja":
#    #    instruction_data = [BranchType.UnconditionalBranch, instruction.operands[0].immediate + addr]
#
#    if instruction.opcode == "bg.jal":
#        instruction_data = [BranchType.CallDestination, instruction.operands[0].immediate + addr]
#
#    if instruction.opcode == "bg.j":
#        instruction_data = [BranchType.UnconditionalBranch, instruction.operands[0].immediate + addr]
#
#    if instruction.opcode == "bg.bf":
#        instruction_data = [BranchType.UnconditionalBranch, instruction.operands[0].immediate + addr]
#
#    if instruction.opcode == "bg.bnf":
#        instruction_data = [BranchType.UnconditionalBranch, instruction.operands[0].immediate + addr]
#
#    if instruction.opcode == "bg.return":
#        instruction_data = [BranchType.FunctionReturn, 0]

    return instruction, instruction_len, instruction_data

# Initialize the disassembler. This function prepares the opcode definitions for later use.
# First, all "0x..." strings are replaced with their binary representation. Then, create a
# mask for quick identification of the opcode and therefore instruction type. Afterwards,
# this function computates all masks for all opcodes and appends them to the opcode 
# definitions.
def init_disassembler():
    for i in range(0, len(beyond_opcodes)):
        operand_name            = beyond_opcodes[i][OPCODE_DEF_INDEX_OPCODE_NAME]
        operand_definition      = beyond_opcodes[i][OPCODE_DEF_INDEX_OPERANDS]

        print("INSTRUCTION: " + operand_name)

        # 1)
        # Replace the "0x..." opcode definition at the beginning of the strings
        # with their binary representation
        beyond_opcodes[i][OPCODE_DEF_INDEX_OPERAND_DEFINITIONS] = beyond_opcodes[i][OPCODE_DEF_INDEX_OPERAND_DEFINITIONS].replace(' ', '')
        format_str                                              = "{:0" + str(OPCODE_LENGTH) + "b}"
        beyond_opcodes[i][OPCODE_DEF_INDEX_OPERAND_DEFINITIONS] = format_str.format(int(beyond_opcodes[i][OPCODE_DEF_INDEX_OPERAND_DEFINITIONS][:3], 16)) + beyond_opcodes[i][OPCODE_DEF_INDEX_OPERAND_DEFINITIONS][3:]
        instruction_definition                                  = beyond_opcodes[i][OPCODE_DEF_INDEX_OPERAND_DEFINITIONS]
        
        print(instruction_definition)

        # 2)
        # Append a quick opcode check mask. This mask contains only the bits needed
        # for identifying the instruction type.
        operand_mask_0, operand_mask_1 = parse_opcode(instruction_definition)
        beyond_opcodes[i].append(operand_mask_0)
        beyond_opcodes[i].append(operand_mask_1)

        print("Operand mask 0: " + bin(operand_mask_0))
        print("Operand mask 1: " + bin(operand_mask_1))

        # 3)
        # For every opcode, compute the mask and store it in the opcode
        # definition array
        operands                = operand_definition.split(",")

        for operand in operands:
            # Parse the provided operand
            parsed_operand = parse_operand(operand, instruction_definition)
            beyond_opcodes[i].append(parsed_operand)