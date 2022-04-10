from binaryninja.function import InstructionTextToken
from binaryninja.enums import InstructionTextTokenType, BranchType

from enum import Enum

import beyond.utils as utils
import beyond.llil as il

# We need a lookup cache because of my inefficient coding :(
disasm_cache = {}

# Opcodes are 4 bit long
OPCODE_LENGTH = 4

MAX_INST_LEN = 6

# Index positions in the opcode definitions
OPCODE_DEF_INDEX_OPCODE_NAME            = 0
OPCODE_DEF_INDEX_OPERANDS               = 1
OPCODE_DEF_INDEX_OPERAND_DEFINITIONS    = 2
OPCODE_DEF_INSTR_DEC_FLAGS              = 3
OPCODE_LIFTING_LLIL_FUNC                = 4
OPCODE_DEF_INDEX_OPCODE_MASK_0          = 5
OPCODE_DEF_INDEX_OPCODE_MASK_1          = 6
OPCODE_DEF_INDEX_OPERAND_MASKS          = 7

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
        result.append(InstructionTextToken(InstructionTextTokenType.BeginMemoryOperandToken, "["))
        #result.extend(self.operands.visit())

        for operand in self.operands:
            result.append(operand.visit()[0])
            if operand is not self.operands[-1]:
                result.append(InstructionTextToken(InstructionTextTokenType.TextToken, "+"))

        result.append(InstructionTextToken(InstructionTextTokenType.EndMemoryOperandToken, "]"))
        return result

class Instruction():
    operands = []

    opcode = ""

    llil_func = None

    def __init__(self, opcode, operands, llil_func):
        self.opcode = opcode
        self.operands = operands
        self.llil_func = llil_func

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

    def to_llil(self, il):
        return self.llil_func(il, self)

# Used for automatically generating the instruction definitions.
# Definitions partially copied from patched binutils for the Beyond ISA.
beyond_opcodes = [
    ["bt.movi",	    "rD,G",		    "0x0 00 DD DDD0 GGGG", [InstInfo.NONE], il.lift_bt_movi],
    ["bt.addi",	    "rD,G",		    "0x0 00 DD DDD1 GGGG", [InstInfo.NONE], il.lift_bt_addi],
    ["bt.mov",	    "rD,rA",	    "0x0 01 DD DDDA AAAA", [InstInfo.NONE], il.lift_bt_mov],
    ["bt.add",	    "rD,rA",	    "0x0 10 DD DDDA AAAA", [InstInfo.NONE], il.lift_bt_add],
    ["bt.j",	    "T",		    "0x0 11 TT TTTT TTTT", [InstInfo.LSB, InstInfo.BRANCH], il.unimplemented],
    ["bn.sb",	    "N(rA),rB",	    "0x2 00 BB BBBA AAAA NNNN NNNN", [InstInfo.NONE], il.unimplemented],
    ["bn.lbz",	    "rD,N(rA)",	    "0x2 01 DD DDDA AAAA NNNN NNNN", [InstInfo.NONE], il.unimplemented],
    ["bn.sh",	    "M(rA),rB",	    "0x2 10 BB BBBA AAAA 0MMM MMMM", [InstInfo.NONE], il.unimplemented],
    ["bn.lhz",	    "rD,M(rA)",	    "0x2 10 DD DDDA AAAA 1MMM MMMM", [InstInfo.NONE], il.unimplemented],
    ["bn.sw",	    "K(rA),rB",	    "0x2 11 BB BBBA AAAA 00KK KKKK", [InstInfo.NONE], il.unimplemented],
    ["bn.lwz",	    "rD,K(rA)",	    "0x2 11 DD DDDA AAAA 01KK KKKK", [InstInfo.NONE], il.unimplemented],
    ["bn.lws",	    "rD,K(rA)",	    "0x2 11 DD DDDA AAAA 10KK KKKK", [InstInfo.NONE], il.unimplemented],
    ["bn.sd",	    "J(rA),rB",	    "0x2 11 BB BBBA AAAA 110J JJJJ", [InstInfo.NONE], il.unimplemented],
    ["bn.ld",	    "rD,J(rA)",	    "0x2 11 DD DDDA AAAA 111J JJJJ", [InstInfo.NONE], il.unimplemented],
    ["bn.addi",	    "rD,rA,O",	    "0x3 00 DD DDDA AAAA OOOO OOOO", [InstInfo.NONE], il.lift_bn_addi],
    ["bn.andi",	    "rD,rA,N",	    "0x3 01 DD DDDA AAAA NNNN NNNN", [InstInfo.NONE], il.lift_bn_andi],
    ["bn.ori",	    "rD,rA,N",	    "0x3 10 DD DDDA AAAA NNNN NNNN", [InstInfo.NONE], il.lift_bn_ori],
    ["bn.sfeqi",	"rA,O",		    "0x3 11 00 000A AAAA OOOO OOOO", [InstInfo.NONE], il.lift_bn_sfeqi],
    ["bn.sfnei",	"rA,O",		    "0x3 11 00 001A AAAA OOOO OOOO", [InstInfo.NONE], il.lift_bn_sfnei],
    ["bn.sfgesi",	"rA,O",		    "0x3 11 00 010A AAAA OOOO OOOO", [InstInfo.NONE], il.lift_bn_sfgesi],
    ["bn.sfgeui",	"rA,O",		    "0x3 11 00 011A AAAA OOOO OOOO", [InstInfo.UNSIGNED], il.lift_bn_sfgeui],
    ["bn.sfgtsi",	"rA,O",		    "0x3 11 00 100A AAAA OOOO OOOO", [InstInfo.NONE], il.lift_bn_sfgtsi],
    ["bn.sfgtui",	"rA,O",		    "0x3 11 00 101A AAAA OOOO OOOO", [InstInfo.UNSIGNED], il.lift_bn_sfgtui],
    ["bn.sflesi",	"rA,O",		    "0x3 11 00 110A AAAA OOOO OOOO", [InstInfo.NONE], il.lift_bn_sflesi],
    ["bn.sfleui",	"rA,O",		    "0x3 11 00 111A AAAA OOOO OOOO", [InstInfo.UNSIGNED], il.lift_bn_sfleui],
    ["bn.sfltsi",	"rA,O",		    "0x3 11 01 000A AAAA OOOO OOOO", [InstInfo.NONE], il.lift_bn_sfltsi],
    ["bn.sfltui",	"rA,O",		    "0x3 11 01 001A AAAA OOOO OOOO", [InstInfo.UNSIGNED], il.lift_bn_sfltui],
    ["bn.sfeq",	    "rA,rB",	    "0x3 11 01 010A AAAA BBBB B---", [InstInfo.NONE], il.lift_bn_sfeq],
    ["bn.sfne",	    "rA,rB",	    "0x3 11 01 011A AAAA BBBB B---", [InstInfo.NONE], il.lift_bn_sfne],
    ["bn.sfges",	"rA,rB",	    "0x3 11 01 100A AAAA BBBB B---", [InstInfo.NONE], il.lift_bn_sfges],
    ["bn.sfgeu",	"rA,rB",	    "0x3 11 01 101A AAAA BBBB B---", [InstInfo.UNSIGNED], il.lift_bn_sfgeu],
    ["bn.sfgts",	"rA,rB",	    "0x3 11 01 110A AAAA BBBB B---", [InstInfo.NONE], il.lift_bn_sfgts],
    ["bn.sfgtu",	"rA,rB",	    "0x3 11 01 111A AAAA BBBB B---", [InstInfo.UNSIGNED], il.lift_bn_sfgtu],
    ["bn.extbz",	"rD,rA",	    "0x3 11 10 -00A AAAA DDDD D000", [InstInfo.NONE], il.unimplemented],
    ["bn.extbs",	"rD,rA",	    "0x3 11 10 -00A AAAA DDDD D001", [InstInfo.NONE], il.unimplemented],
    ["bn.exthz",	"rD,rA",	    "0x3 11 10 -00A AAAA DDDD D010", [InstInfo.NONE], il.unimplemented],
    ["bn.exths",	"rD,rA",	    "0x3 11 10 -00A AAAA DDDD D011", [InstInfo.NONE], il.unimplemented],
    ["bn.ff1",	    "rD,rA",	    "0x3 11 10 -00A AAAA DDDD D100", [InstInfo.NONE], il.unimplemented],
    ["bn.clz",	    "rD,rA",	    "0x3 11 10 -00A AAAA DDDD D101", [InstInfo.NONE], il.unimplemented],
    ["bn.bitrev",	"rD,rA",	    "0x3 11 10 -00A AAAA DDDD D110", [InstInfo.NONE], il.unimplemented],
    ["bn.swab",	    "rD,rA",	    "0x3 11 10 -00A AAAA DDDD D111", [InstInfo.NONE], il.unimplemented],
    ["bn.mfspr",	"rD,rA",	    "0x3 11 10 -01A AAAA DDDD D000", [InstInfo.NONE], il.unimplemented],
    ["bn.mtspr",	"rA,rB",	    "0x3 11 10 -01A AAAA BBBB B001", [InstInfo.NONE], il.unimplemented],
    ["bn.abs",	    "rD,rA",	    "0x3 11 10 -10A AAAA DDDD D000", [InstInfo.NONE], il.unimplemented],
    ["bn.sqr",	    "rD,rA",	    "0x3 11 10 -10A AAAA DDDD D001", [InstInfo.NONE], il.unimplemented],
    ["bn.sqra",	    "rD,rA",	    "0x3 11 10 -10A AAAA DDDD D010", [InstInfo.NONE], il.unimplemented],
    ["bn.casei",	"rA,N",		    "0x3 11 11 -00A AAAA NNNN NNNN", [InstInfo.NONE], il.unimplemented],
    ["bn.beqi",	    "rB,E,P",	    "0x4 00 00 EEEB BBBB PPPP PPPP", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH], il.unimplemented],
    ["bn.bnei",	    "rB,E,P",	    "0x4 00 01 EEEB BBBB PPPP PPPP", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH], il.unimplemented],
    ["bn.bgesi",	"rB,E,P",	    "0x4 00 10 EEEB BBBB PPPP PPPP", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH], il.unimplemented],
    ["bn.bgtsi",	"rB,E,P",	    "0x4 00 11 EEEB BBBB PPPP PPPP", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH], il.unimplemented],
    ["bn.blesi",	"rB,E,P",	    "0x4 01 00 EEEB BBBB PPPP PPPP", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH], il.unimplemented],
    ["bn.bltsi",	"rB,E,P",	    "0x4 01 01 EEEB BBBB PPPP PPPP", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH], il.unimplemented],
    ["bn.j",	    "Z",		    "0x4 01 10 ZZZZ ZZZZ ZZZZ ZZZZ", [InstInfo.LSB, InstInfo.BRANCH], il.unimplemented],
    ["bn.bf",	    "S",		    "0x4 01 11 0010 SSSS SSSS SSSS", [InstInfo.NONE], il.unimplemented],
    ["bn.bnf",	    "S",		    "0x4 01 11 0011 SSSS SSSS SSSS", [InstInfo.NONE], il.unimplemented],
    ["bn.bo",	    "S",		    "0x4 01 11 0100 SSSS SSSS SSSS", [InstInfo.NONE], il.unimplemented],
    ["bn.bno",	    "S",		    "0x4 01 11 0101 SSSS SSSS SSSS", [InstInfo.NONE], il.unimplemented],
    ["bn.bc",	    "S",		    "0x4 01 11 0110 SSSS SSSS SSSS", [InstInfo.NONE], il.unimplemented],
    ["bn.bnc",	    "S",		    "0x4 01 11 0111 SSSS SSSS SSSS", [InstInfo.NONE], il.unimplemented],
    ["bn.entri",	"F,N",		    "0x4 01 11 1010 FFFF NNNN NNNN", [InstInfo.NONE], il.unimplemented],
    ["bn.reti",	    "F,N",		    "0x4 01 11 1011 FFFF NNNN NNNN", [InstInfo.NONE], il.unimplemented],
    ["bn.rtnei",	"F,N",		    "0x4 01 11 1100 FFFF NNNN NNNN", [InstInfo.NONE], il.unimplemented],
    ["bn.return",	"",		        "0x4 01 11 1101 --00 ---- ----", [InstInfo.RETURN], il.unimplemented],
    ["bn.jalr",	    "rA",		    "0x4 01 11 1101 --01 AAAA A---", [InstInfo.LSB, InstInfo.BRANCH], il.unimplemented],
    ["bn.jr",	    "rA",		    "0x4 01 11 1101 --10 AAAA A---", [InstInfo.LSB, InstInfo.BRANCH], il.unimplemented],
    ["bn.jal",	    "s",		    "0x4 10 ss ssss ssss ssss ssss", [InstInfo.LSB, InstInfo.BRANCH], il.unimplemented],
    ["bn.mlwz",	    "rD,K(rA),C",	"0x5 00 DD DDDA AAAA CCKK KKKK", [InstInfo.NONE], il.unimplemented],
    ["bn.msw",	    "K(rA),rB,C",	"0x5 01 BB BBBA AAAA CCKK KKKK", [InstInfo.NONE], il.unimplemented],
    ["bn.mld",	    "rD,H(rA),C",	"0x5 10 DD DDDA AAAA CC0H HHHH", [InstInfo.NONE], il.unimplemented],
    ["bn.msd",	    "H(rA),rB,C",	"0x5 10 BB BBBA AAAA CC1H HHHH", [InstInfo.NONE], il.unimplemented],
    ["bn.lwza",	    "rD,rA,L",	    "0x5 11 DD DDDA AAAA 1100 LLLL", [InstInfo.NONE], il.unimplemented],
    ["bn.swa",	    "rA,rB,L",	    "0x5 11 BB BBBA AAAA 1101 LLLL", [InstInfo.NONE], il.unimplemented],
    ["bn.and",	    "rD,rA,rB",	    "0x6 00 DD DDDA AAAA BBBB B000", [InstInfo.NONE], il.lift_bn_and],
    ["bn.or",	    "rD,rA,rB",	    "0x6 00 DD DDDA AAAA BBBB B001", [InstInfo.NONE], il.lift_bn_or],
    ["bn.xor",	    "rD,rA,rB",	    "0x6 00 DD DDDA AAAA BBBB B010", [InstInfo.NONE], il.lift_bn_xor],
    ["bn.nand",	    "rD,rA,rB",	    "0x6 00 DD DDDA AAAA BBBB B011", [InstInfo.NONE], il.unimplemented],
    ["bn.add",	    "rD,rA,rB",	    "0x6 00 DD DDDA AAAA BBBB B100", [InstInfo.NONE], il.unimplemented],
    ["bn.sub",	    "rD,rA,rB",	    "0x6 00 DD DDDA AAAA BBBB B101", [InstInfo.NONE], il.unimplemented],
    ["bn.sll",	    "rD,rA,rB",	    "0x6 00 DD DDDA AAAA BBBB B110", [InstInfo.NONE], il.unimplemented],
    ["bn.srl",	    "rD,rA,rB",	    "0x6 00 DD DDDA AAAA BBBB B111", [InstInfo.NONE], il.unimplemented],
    ["bn.sra",	    "rD,rA,rB",	    "0x6 01 DD DDDA AAAA BBBB B000", [InstInfo.NONE], il.unimplemented],
    ["bn.ror",	    "rD,rA,rB",	    "0x6 01 DD DDDA AAAA BBBB B001", [InstInfo.NONE], il.unimplemented],
    ["bn.cmov",	    "rD,rA,rB",	    "0x6 01 DD DDDA AAAA BBBB B010", [InstInfo.NONE], il.unimplemented],
    ["bn.mul",	    "rD,rA,rB",	    "0x6 01 DD DDDA AAAA BBBB B011", [InstInfo.NONE], il.unimplemented],
    ["bn.div",	    "rD,rA,rB",	    "0x6 01 DD DDDA AAAA BBBB B100", [InstInfo.NONE], il.unimplemented],
    ["bn.divu",	    "rD,rA,rB",	    "0x6 01 DD DDDA AAAA BBBB B101", [InstInfo.NONE], il.unimplemented],
    ["bn.mac",	    "rA,rB",	    "0x6 01 00 000A AAAA BBBB B110", [InstInfo.NONE], il.unimplemented],
    ["bn.macs",	    "rA,rB",	    "0x6 01 00 001A AAAA BBBB B110", [InstInfo.NONE], il.unimplemented],
    ["bn.macsu",	"rA,rB",	    "0x6 01 00 010A AAAA BBBB B110", [InstInfo.NONE], il.unimplemented],
    ["bn.macuu",	"rA,rB",	    "0x6 01 00 011A AAAA BBBB B110", [InstInfo.NONE], il.unimplemented],
    ["bn.smactt",	"rA,rB",	    "0x6 01 00 100A AAAA BBBB B110", [InstInfo.NONE], il.unimplemented],
    ["bn.smacbb",	"rA,rB",	    "0x6 01 00 101A AAAA BBBB B110", [InstInfo.NONE], il.unimplemented],
    ["bn.smactb",	"rA,rB",	    "0x6 01 00 110A AAAA BBBB B110", [InstInfo.NONE], il.unimplemented],
    ["bn.umactt",	"rA,rB",	    "0x6 01 00 111A AAAA BBBB B110", [InstInfo.NONE], il.unimplemented],
    ["bn.umacbb",	"rA,rB",	    "0x6 01 01 000A AAAA BBBB B110", [InstInfo.NONE], il.unimplemented],
    ["bn.umactb",	"rA,rB",	    "0x6 01 01 001A AAAA BBBB B110", [InstInfo.NONE], il.unimplemented],
    ["bn.msu",	    "rA,rB",	    "0x6 01 01 010A AAAA BBBB B110", [InstInfo.NONE], il.unimplemented],
    ["bn.msus",	    "rA,rB",	    "0x6 01 01 011A AAAA BBBB B110", [InstInfo.NONE], il.unimplemented],
    ["bn.addc",	    "rD,rA,rB",	    "0x6 01 DD DDDA AAAA BBBB B111", [InstInfo.NONE], il.unimplemented],
    ["bn.subb",	    "rD,rA,rB",	    "0x6 10 DD DDDA AAAA BBBB B000", [InstInfo.NONE], il.unimplemented],
    ["bn.flb",	    "rD,rA,rB",	    "0x6 10 DD DDDA AAAA BBBB B001", [InstInfo.NONE], il.unimplemented],
    ["bn.mulhu",	"rD,rA,rB",	    "0x6 10 DD DDDA AAAA BBBB B010", [InstInfo.NONE], il.unimplemented],
    ["bn.mulh",	    "rD,rA,rB",	    "0x6 10 DD DDDA AAAA BBBB B011", [InstInfo.NONE], il.unimplemented],
    ["bn.mod",	    "rD,rA,rB",	    "0x6 10 DD DDDA AAAA BBBB B100", [InstInfo.NONE], il.unimplemented],
    ["bn.modu",	    "rD,rA,rB",	    "0x6 10 DD DDDA AAAA BBBB B101", [InstInfo.NONE], il.unimplemented],
    ["bn.aadd",	    "rD,rA,rB",	    "0x6 10 DD DDDA AAAA BBBB B110", [InstInfo.NONE], il.unimplemented],
    ["bn.cmpxchg",	"rD,rA,rB",	    "0x6 10 DD DDDA AAAA BBBB B111", [InstInfo.NONE], il.unimplemented],
    ["bn.slli",	    "rD,rA,H",	    "0x6 11 DD DDDA AAAA HHHH H-00", [InstInfo.NONE], il.unimplemented],
    ["bn.srli",	    "rD,rA,H",	    "0x6 11 DD DDDA AAAA HHHH H-01", [InstInfo.NONE], il.unimplemented],
    ["bn.srai",	    "rD,rA,H",	    "0x6 11 DD DDDA AAAA HHHH H-10", [InstInfo.NONE], il.unimplemented],
    ["bn.rori",	    "rD,rA,H",	    "0x6 11 DD DDDA AAAA HHHH H-11", [InstInfo.NONE], il.unimplemented],
    ["fn.add.s",	"rD,rA,rB",	    "0x7 00 DD DDDA AAAA BBBB B000", [InstInfo.NONE], il.unimplemented],
    ["fn.sub.s",	"rD,rA,rB",	    "0x7 00 DD DDDA AAAA BBBB B001", [InstInfo.NONE], il.unimplemented],
    ["fn.mul.s",	"rD,rA,rB",	    "0x7 00 DD DDDA AAAA BBBB B010", [InstInfo.NONE], il.unimplemented],
    ["fn.div.s",	"rD,rA,rB",	    "0x7 00 DD DDDA AAAA BBBB B011", [InstInfo.NONE], il.unimplemented],
    ["bn.adds",	    "rD,rA,rB",	    "0x7 01 DD DDDA AAAA BBBB B000", [InstInfo.NONE], il.unimplemented],
    ["bn.subs",	    "rD,rA,rB",	    "0x7 01 DD DDDA AAAA BBBB B001", [InstInfo.NONE], il.unimplemented],
    ["bn.xaadd",	"rD,rA,rB",	    "0x7 01 DD DDDA AAAA BBBB B010", [InstInfo.NONE], il.unimplemented],
    ["bn.xcmpxchg", "rD,rA,rB",	    "0x7 01 DD DDDA AAAA BBBB B011", [InstInfo.NONE], il.unimplemented],
    ["bn.max",	    "rD,rA,rB",	    "0x7 01 DD DDDA AAAA BBBB B100", [InstInfo.NONE], il.unimplemented],
    ["bn.min",	    "rD,rA,rB",	    "0x7 01 DD DDDA AAAA BBBB B101", [InstInfo.NONE], il.unimplemented],
    ["bn.lim",	    "rD,rA,rB",	    "0x7 01 DD DDDA AAAA BBBB B110", [InstInfo.NONE], il.unimplemented],
    ["bn.slls",	    "rD,rA,rB",	    "0x7 10 DD DDDA AAAA BBBB B-00", [InstInfo.NONE], il.unimplemented],
    ["bn.sllis",	"rD,rA,H",	    "0x7 10 DD DDDA AAAA HHHH H-01", [InstInfo.NONE], il.unimplemented],
    ["fn.ftoi.s",	"rD,rA",	    "0x7 11 10 --0A AAAA DDDD D000", [InstInfo.NONE], il.unimplemented],
    ["fn.itof.s",	"rD,rA",	    "0x7 11 10 --0A AAAA DDDD D001", [InstInfo.NONE], il.unimplemented],
    ["bw.sb",	    "h(rA),rB",	    "0x8 00 BB BBBA AAAA hhhh hhhh hhhh hhhh hhhh hhhh hhhh hhhh", [InstInfo.NONE], il.unimplemented],
    ["bw.lbz",	    "rD,h(rA)",	    "0x8 01 DD DDDA AAAA hhhh hhhh hhhh hhhh hhhh hhhh hhhh hhhh", [InstInfo.NONE], il.unimplemented],
    ["bw.sh",	    "i(rA),rB",	    "0x8 10 BB BBBA AAAA 0iii iiii iiii iiii iiii iiii iiii iiii", [InstInfo.NONE], il.unimplemented],
    ["bw.lhz",	    "rD,i(rA)",	    "0x8 10 DD DDDA AAAA 1iii iiii iiii iiii iiii iiii iiii iiii", [InstInfo.NONE], il.unimplemented],
    ["bw.sw",	    "w(rA),rB",	    "0x8 11 BB BBBA AAAA 00ww wwww wwww wwww wwww wwww wwww wwww", [InstInfo.NONE], il.unimplemented],
    ["bw.lwz",	    "rD,w(rA)",	    "0x8 11 DD DDDA AAAA 01ww wwww wwww wwww wwww wwww wwww wwww", [InstInfo.NONE], il.unimplemented],
    ["bw.lws",	    "rD,w(rA)",	    "0x8 11 DD DDDA AAAA 10ww wwww wwww wwww wwww wwww wwww wwww", [InstInfo.NONE], il.unimplemented],
    ["bw.sd",	    "v(rA),rB",	    "0x8 11 BB BBBA AAAA 110v vvvv vvvv vvvv vvvv vvvv vvvv vvvv", [InstInfo.NONE], il.unimplemented],
    ["bw.ld",	    "rD,v(rA)",	    "0x8 11 DD DDDA AAAA 111v vvvv vvvv vvvv vvvv vvvv vvvv vvvv", [InstInfo.NONE], il.unimplemented],
    ["bw.addi",	    "rD,rA,g",	    "0x9 00 DD DDDA AAAA gggg gggg gggg gggg gggg gggg gggg gggg", [InstInfo.NONE], il.lift_bn_addi],
    ["bw.andi",	    "rD,rA,h",	    "0x9 01 DD DDDA AAAA hhhh hhhh hhhh hhhh hhhh hhhh hhhh hhhh", [InstInfo.NONE], il.lift_bn_andi],
    ["bw.ori",	    "rD,rA,h",	    "0x9 10 DD DDDA AAAA hhhh hhhh hhhh hhhh hhhh hhhh hhhh hhhh", [InstInfo.NONE], il.lift_bn_ori],
    ["bw.sfeqi",	"rA,g",		    "0x9 11 01 10-A AAAA gggg gggg gggg gggg gggg gggg gggg gggg", [InstInfo.NONE], il.lift_bn_sfeqi],
    ["bw.sfnei",	"rA,g",		    "0x9 11 01 11-A AAAA gggg gggg gggg gggg gggg gggg gggg gggg", [InstInfo.NONE], il.lift_bn_sfnei],
    ["bw.sfgesi",	"rA,g",		    "0x9 11 10 00-A AAAA gggg gggg gggg gggg gggg gggg gggg gggg", [InstInfo.NONE], il.lift_bn_sfgesi],
    ["bw.sfgeui",	"rA,g",		    "0x9 11 10 01-A AAAA gggg gggg gggg gggg gggg gggg gggg gggg", [InstInfo.UNSIGNED], il.lift_bn_sfgeui],
    ["bw.sfgtsi",	"rA,g",		    "0x9 11 10 10-A AAAA gggg gggg gggg gggg gggg gggg gggg gggg", [InstInfo.NONE], il.lift_bn_sfgtsi],
    ["bw.sfgtui",	"rA,g",		    "0x9 11 10 11-A AAAA gggg gggg gggg gggg gggg gggg gggg gggg", [InstInfo.UNSIGNED], il.lift_bn_sfgtui],
    ["bw.sflesi",	"rA,g",		    "0x9 11 11 00-A AAAA gggg gggg gggg gggg gggg gggg gggg gggg", [InstInfo.NONE], il.lift_bn_sflesi],
    ["bw.sfleui",	"rA,g",		    "0x9 11 11 01-A AAAA gggg gggg gggg gggg gggg gggg gggg gggg", [InstInfo.UNSIGNED], il.lift_bn_sfleui],
    ["bw.sfltsi",	"rA,g",		    "0x9 11 11 10-A AAAA gggg gggg gggg gggg gggg gggg gggg gggg", [InstInfo.NONE], il.lift_bn_sfltsi],
    ["bw.sfltui",	"rA,g",		    "0x9 11 11 11-A AAAA gggg gggg gggg gggg gggg gggg gggg gggg", [InstInfo.UNSIGNED], il.lift_bn_sfltui],
    ["bw.beqi",	    "rB,I,u",	    "0xa 00 00 00II IIIB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH], il.unimplemented],
    ["bw.bnei",	    "rB,I,u",	    "0xa 00 00 01II IIIB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH], il.unimplemented],
    ["bw.bgesi",	"rB,I,u",	    "0xa 00 00 10II IIIB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH], il.unimplemented],
    ["bw.bgtsi",	"rB,I,u",	    "0xa 00 00 11II IIIB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH], il.unimplemented],
    ["bw.blesi",	"rB,I,u",	    "0xa 00 01 00II IIIB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH], il.unimplemented],
    ["bw.bltsi",	"rB,I,u",	    "0xa 00 01 01II IIIB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH], il.unimplemented],
    ["bw.bgeui",	"rB,I,u",	    "0xa 00 01 10II IIIB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH], il.unimplemented],
    ["bw.bgtui",	"rB,I,u",	    "0xa 00 01 11II IIIB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH], il.unimplemented],
    ["bw.bleui",	"rB,I,u",	    "0xa 00 10 00II IIIB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH], il.unimplemented],
    ["bw.bltui",	"rB,I,u",	    "0xa 00 10 01II IIIB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH], il.unimplemented],
    ["bw.beq",	    "rA,rB,u",	    "0xa 00 10 10AA AAAB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH], il.unimplemented],
    ["bw.bne",	    "rA,rB,u",	    "0xa 00 10 11AA AAAB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH], il.unimplemented],
    ["bw.bges",	    "rA,rB,u",	    "0xa 00 11 00AA AAAB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH], il.unimplemented],
    ["bw.bgts",	    "rA,rB,u",	    "0xa 00 11 01AA AAAB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH], il.unimplemented],
    ["bw.bgeu",	    "rA,rB,u",	    "0xa 00 11 10AA AAAB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH], il.unimplemented],
    ["bw.bgtu",	    "rA,rB,u",	    "0xa 00 11 11AA AAAB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH], il.unimplemented],
    ["bw.jal",	    "z",		    "0xa 01 00 00-- ---- zzzz zzzz zzzz zzzz zzzz zzzz zzzz zzzz", [InstInfo.LSB, InstInfo.CALL], il.unimplemented],
    ["bw.j",	    "z",		    "0xa 01 00 01-- ---- zzzz zzzz zzzz zzzz zzzz zzzz zzzz zzzz", [InstInfo.LSB, InstInfo.BRANCH], il.unimplemented],
    ["bw.bf",	    "z",		    "0xa 01 00 10-- ---- zzzz zzzz zzzz zzzz zzzz zzzz zzzz zzzz", [InstInfo.NONE], il.unimplemented],
    ["bw.bnf",	    "z",		    "0xa 01 00 11-- ---- zzzz zzzz zzzz zzzz zzzz zzzz zzzz zzzz", [InstInfo.NONE], il.unimplemented],
    ["bw.ja",	    "g",		    "0xa 01 01 00-- ---- gggg gggg gggg gggg gggg gggg gggg gggg", [InstInfo.NONE], il.unimplemented],
    ["bw.jma",	    "rD,z",		    "0xa 01 01 01DD DDD0 zzzz zzzz zzzz zzzz zzzz zzzz zzzz zzzz", [InstInfo.NONE], il.unimplemented],
    ["bw.jmal",	    "rD,z",		    "0xa 01 01 01DD DDD1 zzzz zzzz zzzz zzzz zzzz zzzz zzzz zzzz", [InstInfo.NONE], il.unimplemented],
    ["bw.lma",	    "rD,z",		    "0xa 01 01 10DD DDD0 zzzz zzzz zzzz zzzz zzzz zzzz zzzz zzzz", [InstInfo.NONE], il.unimplemented],
    ["bw.sma",	    "rB,z",		    "0xa 01 01 10BB BBB1 zzzz zzzz zzzz zzzz zzzz zzzz zzzz zzzz", [InstInfo.NONE], il.unimplemented],
    ["bw.casewi",	"rB,z",		    "0xa 01 01 11BB BBB0 zzzz zzzz zzzz zzzz zzzz zzzz zzzz zzzz", [InstInfo.NONE], il.unimplemented],
    ["fw.beq.s",	"rA,rB,u",	    "0xa 01 10 00AA AAAB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu", [InstInfo.NONE], il.unimplemented],
    ["fw.bne.s",	"rA,rB,u",	    "0xa 01 10 01AA AAAB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu", [InstInfo.NONE], il.unimplemented],
    ["fw.bge.s",	"rA,rB,u",	    "0xa 01 10 10AA AAAB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu", [InstInfo.NONE], il.unimplemented],
    ["fw.bgt.s",	"rA,rB,u",	    "0xa 01 10 11AA AAAB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu", [InstInfo.NONE], il.unimplemented],
    ["bw.mfspr",	"rD,rA,o",	    "0xa 10 DD DDDA AAAA oooo oooo oooo oooo oooo oooo ---- -000", [InstInfo.NONE], il.unimplemented],
    ["bw.mtspr",	"rA,rB,o",	    "0xa 10 BB BBBA AAAA oooo oooo oooo oooo oooo oooo ---- -001", [InstInfo.NONE], il.unimplemented],
    ["bw.addci",	"rD,rA,p",	    "0xa 10 DD DDDA AAAA pppp pppp pppp pppp pppp pppp ---- -010", [InstInfo.NONE], il.unimplemented],
    ["bw.divi",	    "rD,rA,p",	    "0xa 10 DD DDDA AAAA pppp pppp pppp pppp pppp pppp ---- -011", [InstInfo.NONE], il.unimplemented],
    ["bw.divui",	"rD,rA,o",	    "0xa 10 DD DDDA AAAA oooo oooo oooo oooo oooo oooo ---- -100", [InstInfo.NONE], il.unimplemented],
    ["bw.muli",	    "rD,rA,p",	    "0xa 10 DD DDDA AAAA pppp pppp pppp pppp pppp pppp ---- -101", [InstInfo.NONE], il.unimplemented],
    ["bw.xori",	    "rD,rA,p",	    "0xa 10 DD DDDA AAAA pppp pppp pppp pppp pppp pppp ---- -110", [InstInfo.NONE], il.unimplemented],
    ["bw.mulas",	"rD,rA,rB,H",	"0xa 11 DD DDDA AAAA BBBB BHHH HH-- ---- ---- ---- --00 0000", [InstInfo.NONE], il.unimplemented],
    ["bw.muluas",	"rD,rA,rB,H",	"0xa 11 DD DDDA AAAA BBBB BHHH HH-- ---- ---- ---- --00 0001", [InstInfo.NONE], il.unimplemented],
    ["bw.mulras",	"rD,rA,rB,H",	"0xa 11 DD DDDA AAAA BBBB BHHH HH-- ---- ---- ---- --00 0010", [InstInfo.NONE], il.unimplemented],
    ["bw.muluras",	"rD,rA,rB,H",	"0xa 11 DD DDDA AAAA BBBB BHHH HH-- ---- ---- ---- --00 0011", [InstInfo.NONE], il.unimplemented],
    ["bw.mulsu",	"rD,rA,rB",	    "0xa 11 DD DDDA AAAA BBBB B--- ---- ---- ---- ---- --00 0100", [InstInfo.NONE], il.unimplemented],
    ["bw.mulhsu",	"rD,rA,rB",	    "0xa 11 DD DDDA AAAA BBBB B--- ---- ---- ---- ---- --00 0101", [InstInfo.NONE], il.unimplemented],
    ["bw.mulhlsu",	"rD,rQ,rA,rB",	"0xa 11 DD DDDA AAAA BBBB BQQQ QQ-- ---- ---- ---- --00 0110", [InstInfo.NONE], il.unimplemented],       
    ["bw.smultt",	"rD,rA,rB",	    "0xa 11 DD DDDA AAAA BBBB B--- ---- ---- ---- ---- --10 0000", [InstInfo.NONE], il.unimplemented],
    ["bw.smultb",	"rD,rA,rB",	    "0xa 11 DD DDDA AAAA BBBB B--- ---- ---- ---- ---- --10 0001", [InstInfo.NONE], il.unimplemented],
    ["bw.smulbb",	"rD,rA,rB",	    "0xa 11 DD DDDA AAAA BBBB B--- ---- ---- ---- ---- --10 0010", [InstInfo.NONE], il.unimplemented],
    ["bw.smulwb",	"rD,rA,rB",	    "0xa 11 DD DDDA AAAA BBBB B--- ---- ---- ---- ---- --10 0011", [InstInfo.NONE], il.unimplemented],
    ["bw.smulwt",	"rD,rA,rB",	    "0xa 11 DD DDDA AAAA BBBB B--- ---- ---- ---- ---- --10 0100", [InstInfo.NONE], il.unimplemented],
    ["bw.umultt",	"rD,rA,rB",	    "0xa 11 DD DDDA AAAA BBBB B--- ---- ---- ---- ---- --10 1000", [InstInfo.NONE], il.unimplemented],
    ["bw.umultb",	"rD,rA,rB",	    "0xa 11 DD DDDA AAAA BBBB B--- ---- ---- ---- ---- --10 1001", [InstInfo.NONE], il.unimplemented],
    ["bw.umulbb",	"rD,rA,rB",	    "0xa 11 DD DDDA AAAA BBBB B--- ---- ---- ---- ---- --10 1010", [InstInfo.NONE], il.unimplemented],
    ["bw.umulwb",	"rD,rA,rB",	    "0xa 11 DD DDDA AAAA BBBB B--- ---- ---- ---- ---- --10 1011", [InstInfo.NONE], il.unimplemented],
    ["bw.umulwt",	"rD,rA,rB",	    "0xa 11 DD DDDA AAAA BBBB B--- ---- ---- ---- ---- --10 1100", [InstInfo.NONE], il.unimplemented],
    ["bw.smadtt",	"rD,rA,rB,rR",	"0xa 11 DD DDDA AAAA BBBB BRRR RR-- ---- ---- ---- --11 0000", [InstInfo.NONE], il.unimplemented],
    ["bw.smadtb",	"rD,rA,rB,rR",	"0xa 11 DD DDDA AAAA BBBB BRRR RR-- ---- ---- ---- --11 0001", [InstInfo.NONE], il.unimplemented],
    ["bw.smadbb",	"rD,rA,rB,rR",	"0xa 11 DD DDDA AAAA BBBB BRRR RR-- ---- ---- ---- --11 0010", [InstInfo.NONE], il.unimplemented],
    ["bw.smadwb",	"rD,rA,rB,rR",	"0xa 11 DD DDDA AAAA BBBB BRRR RR-- ---- ---- ---- --11 0011", [InstInfo.NONE], il.unimplemented],
    ["bw.smadwt",	"rD,rA,rB,rR",	"0xa 11 DD DDDA AAAA BBBB BRRR RR-- ---- ---- ---- --11 0100", [InstInfo.NONE], il.unimplemented],
    ["bw.umadtt",	"rD,rA,rB,rR",	"0xa 11 DD DDDA AAAA BBBB BRRR RR-- ---- ---- ---- --11 1000", [InstInfo.NONE], il.unimplemented],
    ["bw.umadtb",	"rD,rA,rB,rR",	"0xa 11 DD DDDA AAAA BBBB BRRR RR-- ---- ---- ---- --11 1001", [InstInfo.NONE], il.unimplemented],
    ["bw.umadbb",	"rD,rA,rB,rR",	"0xa 11 DD DDDA AAAA BBBB BRRR RR-- ---- ---- ---- --11 1010", [InstInfo.NONE], il.unimplemented],
    ["bw.umadwb",	"rD,rA,rB,rR",	"0xa 11 DD DDDA AAAA BBBB BRRR RR-- ---- ---- ---- --11 1011", [InstInfo.NONE], il.unimplemented],
    ["bw.umadwt",	"rD,rA,rB,rR",	"0xa 11 DD DDDA AAAA BBBB BRRR RR-- ---- ---- ---- --11 1100", [InstInfo.NONE], il.unimplemented],
    ["bw.copdss",	"rD,rA,rB,y",	"0xb 00 DD DDDA AAAA BBBB Byyy yyyy yyyy yyyy yyyy yyyy yyyy", [InstInfo.NONE], il.unimplemented],
    ["bw.copd",	    "rD,g,H",	    "0xb 01 DD DDDH HHHH gggg gggg gggg gggg gggg gggg gggg gggg", [InstInfo.NONE], il.unimplemented],
    ["bw.cop",	    "g,x",		    "0xb 10 xx xxxx xxxx gggg gggg gggg gggg gggg gggg gggg gggg", [InstInfo.NONE], il.unimplemented],
    ["bg.sb",	    "Y(rA),rB",	    "0xc 00 BB BBBA AAAA YYYY YYYY YYYY YYYY", [InstInfo.NONE], il.unimplemented],
    ["bg.lbz",	    "rD,Y(rA)",	    "0xc 01 DD DDDA AAAA YYYY YYYY YYYY YYYY", [InstInfo.NONE], il.unimplemented],
    ["bg.sh",	    "X(rA),rB",	    "0xc 10 BB BBBA AAAA 0XXX XXXX XXXX XXXX", [InstInfo.NONE], il.unimplemented],
    ["bg.lhz",	    "rD,X(rA)",	    "0xc 10 DD DDDA AAAA 1XXX XXXX XXXX XXXX", [InstInfo.NONE], il.unimplemented],
    ["bg.sw",	    "W(rA),rB",	    "0xc 11 BB BBBA AAAA 00WW WWWW WWWW WWWW", [InstInfo.NONE], il.unimplemented],
    ["bg.lwz",	    "rD,W(rA)",	    "0xc 11 DD DDDA AAAA 01WW WWWW WWWW WWWW", [InstInfo.NONE], il.unimplemented],
    ["bg.lws",	    "rD,W(rA)",	    "0xc 11 DD DDDA AAAA 10WW WWWW WWWW WWWW", [InstInfo.NONE], il.unimplemented],
    ["bg.sd",	    "V(rA),rB",	    "0xc 11 BB BBBA AAAA 110V VVVV VVVV VVVV", [InstInfo.NONE], il.unimplemented],
    ["bg.ld",	    "rD,V(rA)",	    "0xc 11 DD DDDA AAAA 111V VVVV VVVV VVVV", [InstInfo.NONE], il.unimplemented],
    ["bg.beqi",	    "rB,I,U",	    "0xd 00 00 00II IIIB BBBB UUUU UUUU UUUU", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH], il.unimplemented],
    ["bg.bnei",	    "rB,I,U",	    "0xd 00 00 01II IIIB BBBB UUUU UUUU UUUU", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH], il.unimplemented],
    ["bg.bgesi",	"rB,I,U",	    "0xd 00 00 10II IIIB BBBB UUUU UUUU UUUU", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH], il.unimplemented],
    ["bg.bgtsi",	"rB,I,U",	    "0xd 00 00 11II IIIB BBBB UUUU UUUU UUUU", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH], il.unimplemented],
    ["bg.blesi",	"rB,I,U",	    "0xd 00 01 00II IIIB BBBB UUUU UUUU UUUU", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH], il.unimplemented],
    ["bg.bltsi",	"rB,I,U",	    "0xd 00 01 01II IIIB BBBB UUUU UUUU UUUU", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH], il.unimplemented],
    ["bg.bgeui",	"rB,I,U",	    "0xd 00 01 10II IIIB BBBB UUUU UUUU UUUU", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH], il.unimplemented],
    ["bg.bgtui",	"rB,I,U",	    "0xd 00 01 11II IIIB BBBB UUUU UUUU UUUU", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH], il.unimplemented],
    ["bg.bleui",	"rB,I,U",	    "0xd 00 10 00II IIIB BBBB UUUU UUUU UUUU", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH], il.unimplemented],
    ["bg.bltui",	"rB,I,U",	    "0xd 00 10 01II IIIB BBBB UUUU UUUU UUUU", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH], il.unimplemented],
    ["bg.beq",	    "rA,rB,U",	    "0xd 00 10 10AA AAAB BBBB UUUU UUUU UUUU", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH], il.unimplemented],
    ["bg.bne",	    "rA,rB,U",	    "0xd 00 10 11AA AAAB BBBB UUUU UUUU UUUU", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH], il.unimplemented],
    ["bg.bges",	    "rA,rB,U",	    "0xd 00 11 00AA AAAB BBBB UUUU UUUU UUUU", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH], il.unimplemented],
    ["bg.bgts",	    "rA,rB,U",	    "0xd 00 11 01AA AAAB BBBB UUUU UUUU UUUU", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH], il.unimplemented],
    ["bg.bgeu",	    "rA,rB,U",	    "0xd 00 11 10AA AAAB BBBB UUUU UUUU UUUU", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH], il.unimplemented],
    ["bg.bgtu",	    "rA,rB,U",	    "0xd 00 11 11AA AAAB BBBB UUUU UUUU UUUU", [InstInfo.LSB, InstInfo.CONDITIONAL_BRANCH], il.unimplemented],
    ["bg.jal",	    "t",		    "0xd 01 00 tttt tttt tttt tttt tttt tttt", [InstInfo.LSB, InstInfo.CALL], il.unimplemented],
    ["bg.j",	    "t",		    "0xd 01 01 tttt tttt tttt tttt tttt tttt", [InstInfo.LSB, InstInfo.BRANCH], il.unimplemented],
    ["bg.bf",	    "t",		    "0xd 01 10 tttt tttt tttt tttt tttt tttt", [InstInfo.LSB], il.unimplemented],
    ["bg.bnf",	    "t",		    "0xd 01 11 tttt tttt tttt tttt tttt tttt", [InstInfo.LSB], il.unimplemented],
    ["bg.addi",	    "rD,rA,Y",	    "0xd 10 DD DDDA AAAA YYYY YYYY YYYY YYYY", [InstInfo.NONE], il.lift_bn_addi],
    ["fg.beq.s",	"rA,rB,U",	    "0xd 11 00 00AA AAAB BBBB UUUU UUUU UUUU", [InstInfo.NONE], il.unimplemented],
    ["fg.bne.s",	"rA,rB,U",	    "0xd 11 00 01AA AAAB BBBB UUUU UUUU UUUU", [InstInfo.NONE], il.unimplemented],
    ["fg.bge.s",	"rA,rB,U",	    "0xd 11 00 10AA AAAB BBBB UUUU UUUU UUUU", [InstInfo.NONE], il.unimplemented],
    ["fg.bgt.s",	"rA,rB,U",	    "0xd 11 00 11AA AAAB BBBB UUUU UUUU UUUU", [InstInfo.NONE], il.unimplemented]
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

    cached_instruction, cached_instruction_len, cached_instruction_data = lookup_disasm_cache(addr, data[:MAX_INST_LEN])
    if cached_instruction is not None and cached_instruction_len is not None:
        return cached_instruction, cached_instruction_len, cached_instruction_data

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
            llil_func               = beyond_opcodes[i][OPCODE_LIFTING_LLIL_FUNC]
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

                    # Only the last immediate deternines the jump target address
                    if opcodes[-1] is opcode and InstInfo.CONDITIONAL_BRANCH in instr_dec_flags:
                        immediate = immediate + addr

                    instructionOperands.append(ImmediateOperand(immediate))
                #break
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
            instruction = Instruction(operand_name, instructionOperands, llil_func)

            print(str(instruction))

            found = True
            break

        if found:
            break

    if instruction == None:
        return None, 0, instruction_data

    if InstInfo.BRANCH in instr_dec_flags:
        if len(instruction.operands) > 0:
            if type(instruction.operands[0]) is ImmediateOperand:
                instruction_data = [BranchType.UnconditionalBranch, instruction.operands[0].immediate]
            elif type(instruction.operands[0]) is RegisterOperand:
                instruction_data = [BranchType.UnresolvedBranch]

    if InstInfo.CALL in instr_dec_flags:
        if len(instruction.operands) > 0:
            instruction_data = [BranchType.CallDestination, instruction.operands[0].immediate]

    if InstInfo.INDIRECT in instr_dec_flags:
        if len(instruction.operands) > 0:
            instruction_data = [BranchType.IndirectBranch]
    
    if InstInfo.RETURN in instr_dec_flags:
        if len(instruction.operands) > 0:
            instruction_data = [BranchType.FunctionReturn, instruction.operands[0].immediate]
    
    if InstInfo.CONDITIONAL_BRANCH in instr_dec_flags:
        if len(instruction.operands) > 0:
            instruction_data = [BranchType.TrueBranch, instruction.operands[-1].immediate, BranchType.FalseBranch, addr + instruction_len]

    # There are multiple instructions which can look like a return.
    # These are:
    #   bn.return
    #   bn.jr r9
    # TODO: add more

    is_return = False
    if opcode == "bn.jr":
        if instruction.operand[0].register == Register.r9:
            is_return = True

    if InstInfo.RETURN in instr_dec_flags:
        is_return = True

    if is_return:
        instruction_data = [BranchType.FunctionReturn]

    # Update the disassembly cache
    update_disasm_cache(addr, data[:MAX_INST_LEN], instruction, instruction_len, instruction_data)

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

def instruction_to_llil(data, addr, il):
    cached_instruction, cached_instruction_len, _ = lookup_disasm_cache(addr, data[:MAX_INST_LEN])

    if cached_instruction is None or cached_instruction_len is None:
        instruction, _, _ = disassemble(data, addr)
        
        if instruction is None:
            return None, 0

        cached_instruction = instruction

    expr = cached_instruction.to_llil(il)

    return expr, cached_instruction_len

def lookup_disasm_cache(addr, data):
    global disasm_cache

    if addr in disasm_cache:
        if data == disasm_cache[addr][0]:
            print("lookup_disasm_cache success")
            return disasm_cache[addr][1], disasm_cache[addr][2], disasm_cache[addr][3]
    
    return None, None, None

def update_disasm_cache(addr, data, instruction, instruction_len, instruction_data):
    global disasm_cache

    disasm_cache[addr] = (data, instruction, instruction_len, instruction_data)