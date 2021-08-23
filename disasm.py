from binaryninja.function import InstructionTextToken
from binaryninja.enums import InstructionTextTokenType, BranchType

from enum import Enum

import beyond_isa.utils as utils
#import utils

# Opcodes are 4 bit long
OPCODE_LENGTH = 4

# Index positions in the opcode definitions
OPCODE_DEF_INDEX_OPCODE_NAME            = 0
OPCODE_DEF_INDEX_OPERANDS               = 1
OPCODE_DEF_INDEX_OPERAND_DEFINITIONS    = 2
OPCODE_DEF_INDEX_OPCODE_MASK_0          = 3
OPCODE_DEF_INDEX_OPCODE_MASK_1          = 4
OPCODE_DEF_INDEX_OPERAND_MASKS          = 5

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
        result.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, str(self.immediate)))
        return result

class AddressOperand(Operand):
    address = 0

    def __init__(self, address):
        self.address = address

    def __str__(self):
        return "<AddressOperand address: %s>" % (self.address)

    def visit(self):
        result = []
        result.append(InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, str(self.address)))
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
    ["bt.movi",	    "rD,G",		    "0x0 00 DD DDD0 GGGG"],
    ["bt.addi",	    "rD,G",		    "0x0 00 DD DDD1 GGGG"],
    ["bt.mov",	    "rD,rA",	    "0x0 01 DD DDDA AAAA"],
    ["bt.add",	    "rD,rA",	    "0x0 10 DD DDDA AAAA"],
    ["bt.j",	    "T",		    "0x0 11 TT TTTT TTTT"],
    ["bn.sb",	    "N(rA),rB",	    "0x2 00 BB BBBA AAAA NNNN NNNN"],
    ["bn.lbz",	    "rD,N(rA)",	    "0x2 01 DD DDDA AAAA NNNN NNNN"],
    ["bn.sh",	    "M(rA),rB",	    "0x2 10 BB BBBA AAAA 0MMM MMMM"],
    ["bn.lhz",	    "rD,M(rA)",	    "0x2 10 DD DDDA AAAA 1MMM MMMM"],
    ["bn.sw",	    "K(rA),rB",	    "0x2 11 BB BBBA AAAA 00KK KKKK"],
    ["bn.lwz",	    "rD,K(rA)",	    "0x2 11 DD DDDA AAAA 01KK KKKK"],
    ["bn.lws",	    "rD,K(rA)",	    "0x2 11 DD DDDA AAAA 10KK KKKK"],
    ["bn.sd",	    "J(rA),rB",	    "0x2 11 BB BBBA AAAA 110J JJJJ"],
    ["bn.ld",	    "rD,J(rA)",	    "0x2 11 DD DDDA AAAA 111J JJJJ"],
    ["bn.addi",	    "rD,rA,O",	    "0x3 00 DD DDDA AAAA OOOO OOOO"],
    ["bn.andi",	    "rD,rA,N",	    "0x3 01 DD DDDA AAAA NNNN NNNN"],
    ["bn.ori",	    "rD,rA,N",	    "0x3 10 DD DDDA AAAA NNNN NNNN"],
    ["bn.sfeqi",	"rA,O",		    "0x3 11 00 000A AAAA OOOO OOOO"],
    ["bn.sfnei",	"rA,O",		    "0x3 11 00 001A AAAA OOOO OOOO"],
    ["bn.sfgesi",	"rA,O",		    "0x3 11 00 010A AAAA OOOO OOOO"],
    ["bn.sfgeui",	"rA,O",		    "0x3 11 00 011A AAAA OOOO OOOO"],
    ["bn.sfgtsi",	"rA,O",		    "0x3 11 00 100A AAAA OOOO OOOO"],
    ["bn.sfgtui",	"rA,O",		    "0x3 11 00 101A AAAA OOOO OOOO"],
    ["bn.sflesi",	"rA,O",		    "0x3 11 00 110A AAAA OOOO OOOO"],
    ["bn.sfleui",	"rA,O",		    "0x3 11 00 111A AAAA OOOO OOOO"],
    ["bn.sfltsi",	"rA,O",		    "0x3 11 01 000A AAAA OOOO OOOO"],
    ["bn.sfltui",	"rA,O",		    "0x3 11 01 001A AAAA OOOO OOOO"],
    ["bn.sfeq",	    "rA,rB",	    "0x3 11 01 010A AAAA BBBB B---"],
    ["bn.sfne",	    "rA,rB",	    "0x3 11 01 011A AAAA BBBB B---"],
    ["bn.sfges",	"rA,rB",	    "0x3 11 01 100A AAAA BBBB B---"],
    ["bn.sfgeu",	"rA,rB",	    "0x3 11 01 101A AAAA BBBB B---"],
    ["bn.sfgts",	"rA,rB",	    "0x3 11 01 110A AAAA BBBB B---"],
    ["bn.sfgtu",	"rA,rB",	    "0x3 11 01 111A AAAA BBBB B---"],
    ["bn.extbz",	"rD,rA",	    "0x3 11 10 -00A AAAA DDDD D000"],
    ["bn.extbs",	"rD,rA",	    "0x3 11 10 -00A AAAA DDDD D001"],
    ["bn.exthz",	"rD,rA",	    "0x3 11 10 -00A AAAA DDDD D010"],
    ["bn.exths",	"rD,rA",	    "0x3 11 10 -00A AAAA DDDD D011"],
    ["bn.ff1",	    "rD,rA",	    "0x3 11 10 -00A AAAA DDDD D100"],
    ["bn.clz",	    "rD,rA",	    "0x3 11 10 -00A AAAA DDDD D101"],
    ["bn.bitrev",	"rD,rA",	    "0x3 11 10 -00A AAAA DDDD D110"],
    ["bn.swab",	    "rD,rA",	    "0x3 11 10 -00A AAAA DDDD D111"],
    ["bn.mfspr",	"rD,rA",	    "0x3 11 10 -01A AAAA DDDD D000"],
    ["bn.mtspr",	"rA,rB",	    "0x3 11 10 -01A AAAA BBBB B001"],
    ["bn.abs",	    "rD,rA",	    "0x3 11 10 -10A AAAA DDDD D000"],
    ["bn.sqr",	    "rD,rA",	    "0x3 11 10 -10A AAAA DDDD D001"],
    ["bn.sqra",	    "rD,rA",	    "0x3 11 10 -10A AAAA DDDD D010"],
    ["bn.casei",	"rA,N",		    "0x3 11 11 -00A AAAA NNNN NNNN"],
    ["bn.beqi",	    "rB,E,P",	    "0x4 00 00 EEEB BBBB PPPP PPPP"],
    ["bn.bnei",	    "rB,E,P",	    "0x4 00 01 EEEB BBBB PPPP PPPP"],
    ["bn.bgesi",	"rB,E,P",	    "0x4 00 10 EEEB BBBB PPPP PPPP"],
    ["bn.bgtsi",	"rB,E,P",	    "0x4 00 11 EEEB BBBB PPPP PPPP"],
    ["bn.blesi",	"rB,E,P",	    "0x4 01 00 EEEB BBBB PPPP PPPP"],
    ["bn.bltsi",	"rB,E,P",	    "0x4 01 01 EEEB BBBB PPPP PPPP"],
    ["bn.j",	    "Z",		    "0x4 01 10 ZZZZ ZZZZ ZZZZ ZZZZ"],
    ["bn.bf",	    "S",		    "0x4 01 11 0010 SSSS SSSS SSSS"],
    ["bn.bnf",	    "S",		    "0x4 01 11 0011 SSSS SSSS SSSS"],
    ["bn.bo",	    "S",		    "0x4 01 11 0100 SSSS SSSS SSSS"],
    ["bn.bno",	    "S",		    "0x4 01 11 0101 SSSS SSSS SSSS"],
    ["bn.bc",	    "S",		    "0x4 01 11 0110 SSSS SSSS SSSS"],
    ["bn.bnc",	    "S",		    "0x4 01 11 0111 SSSS SSSS SSSS"],
    ["bn.entri",	"F,N",		    "0x4 01 11 1010 FFFF NNNN NNNN"],
    ["bn.reti",	    "F,N",		    "0x4 01 11 1011 FFFF NNNN NNNN"],
    ["bn.rtnei",	"F,N",		    "0x4 01 11 1100 FFFF NNNN NNNN"],
    ["bn.return",	"",		        "0x4 01 11 1101 --00 ---- ----"],
    ["bn.jalr",	    "rA",		    "0x4 01 11 1101 --01 AAAA A---"],
    ["bn.jr",	    "rA",		    "0x4 01 11 1101 --10 AAAA A---"],
    ["bn.jal",	    "s",		    "0x4 10 ss ssss ssss ssss ssss"],
    ["bn.mlwz",	    "rD,K(rA),C",	"0x5 00 DD DDDA AAAA CCKK KKKK"],
    ["bn.msw",	    "K(rA),rB,C",	"0x5 01 BB BBBA AAAA CCKK KKKK"],
    ["bn.mld",	    "rD,H(rA),C",	"0x5 10 DD DDDA AAAA CC0H HHHH"],
    ["bn.msd",	    "H(rA),rB,C",	"0x5 10 BB BBBA AAAA CC1H HHHH"],
    ["bn.lwza",	    "rD,rA,L",	    "0x5 11 DD DDDA AAAA 1100 LLLL"],
    ["bn.swa",	    "rA,rB,L",	    "0x5 11 BB BBBA AAAA 1101 LLLL"],
    ["bn.and",	    "rD,rA,rB",	    "0x6 00 DD DDDA AAAA BBBB B000"],
    ["bn.or",	    "rD,rA,rB",	    "0x6 00 DD DDDA AAAA BBBB B001"],
    ["bn.xor",	    "rD,rA,rB",	    "0x6 00 DD DDDA AAAA BBBB B010"],
    ["bn.nand",	    "rD,rA,rB",	    "0x6 00 DD DDDA AAAA BBBB B011"],
    ["bn.add",	    "rD,rA,rB",	    "0x6 00 DD DDDA AAAA BBBB B100"],
    ["bn.sub",	    "rD,rA,rB",	    "0x6 00 DD DDDA AAAA BBBB B101"],
    ["bn.sll",	    "rD,rA,rB",	    "0x6 00 DD DDDA AAAA BBBB B110"],
    ["bn.srl",	    "rD,rA,rB",	    "0x6 00 DD DDDA AAAA BBBB B111"],
    ["bn.sra",	    "rD,rA,rB",	    "0x6 01 DD DDDA AAAA BBBB B000"],
    ["bn.ror",	    "rD,rA,rB",	    "0x6 01 DD DDDA AAAA BBBB B001"],
    ["bn.cmov",	    "rD,rA,rB",	    "0x6 01 DD DDDA AAAA BBBB B010"],
    ["bn.mul",	    "rD,rA,rB",	    "0x6 01 DD DDDA AAAA BBBB B011"],
    ["bn.div",	    "rD,rA,rB",	    "0x6 01 DD DDDA AAAA BBBB B100"],
    ["bn.divu",	    "rD,rA,rB",	    "0x6 01 DD DDDA AAAA BBBB B101"],
    ["bn.mac",	    "rA,rB",	    "0x6 01 00 000A AAAA BBBB B110"],
    ["bn.macs",	    "rA,rB",	    "0x6 01 00 001A AAAA BBBB B110"],
    ["bn.macsu",	"rA,rB",	    "0x6 01 00 010A AAAA BBBB B110"],
    ["bn.macuu",	"rA,rB",	    "0x6 01 00 011A AAAA BBBB B110"],
    ["bn.smactt",	"rA,rB",	    "0x6 01 00 100A AAAA BBBB B110"],
    ["bn.smacbb",	"rA,rB",	    "0x6 01 00 101A AAAA BBBB B110"],
    ["bn.smactb",	"rA,rB",	    "0x6 01 00 110A AAAA BBBB B110"],
    ["bn.umactt",	"rA,rB",	    "0x6 01 00 111A AAAA BBBB B110"],
    ["bn.umacbb",	"rA,rB",	    "0x6 01 01 000A AAAA BBBB B110"],
    ["bn.umactb",	"rA,rB",	    "0x6 01 01 001A AAAA BBBB B110"],
    ["bn.msu",	    "rA,rB",	    "0x6 01 01 010A AAAA BBBB B110"],
    ["bn.msus",	    "rA,rB",	    "0x6 01 01 011A AAAA BBBB B110"],
    ["bn.addc",	    "rD,rA,rB",	    "0x6 01 DD DDDA AAAA BBBB B111"],
    ["bn.subb",	    "rD,rA,rB",	    "0x6 10 DD DDDA AAAA BBBB B000"],
    ["bn.flb",	    "rD,rA,rB",	    "0x6 10 DD DDDA AAAA BBBB B001"],
    ["bn.mulhu",	"rD,rA,rB",	    "0x6 10 DD DDDA AAAA BBBB B010"],
    ["bn.mulh",	    "rD,rA,rB",	    "0x6 10 DD DDDA AAAA BBBB B011"],
    ["bn.mod",	    "rD,rA,rB",	    "0x6 10 DD DDDA AAAA BBBB B100"],
    ["bn.modu",	    "rD,rA,rB",	    "0x6 10 DD DDDA AAAA BBBB B101"],
    ["bn.aadd",	    "rD,rA,rB",	    "0x6 10 DD DDDA AAAA BBBB B110"],
    ["bn.cmpxchg",	"rD,rA,rB",	    "0x6 10 DD DDDA AAAA BBBB B111"],
    ["bn.slli",	    "rD,rA,H",	    "0x6 11 DD DDDA AAAA HHHH H-00"],
    ["bn.srli",	    "rD,rA,H",	    "0x6 11 DD DDDA AAAA HHHH H-01"],
    ["bn.srai",	    "rD,rA,H",	    "0x6 11 DD DDDA AAAA HHHH H-10"],
    ["bn.rori",	    "rD,rA,H",	    "0x6 11 DD DDDA AAAA HHHH H-11"],
    ["fn.add.s",	"rD,rA,rB",	    "0x7 00 DD DDDA AAAA BBBB B000"],
    ["fn.sub.s",	"rD,rA,rB",	    "0x7 00 DD DDDA AAAA BBBB B001"],
    ["fn.mul.s",	"rD,rA,rB",	    "0x7 00 DD DDDA AAAA BBBB B010"],
    ["fn.div.s",	"rD,rA,rB",	    "0x7 00 DD DDDA AAAA BBBB B011"],
    ["bn.adds",	    "rD,rA,rB",	    "0x7 01 DD DDDA AAAA BBBB B000"],
    ["bn.subs",	    "rD,rA,rB",	    "0x7 01 DD DDDA AAAA BBBB B001"],
    ["bn.xaadd",	"rD,rA,rB",	    "0x7 01 DD DDDA AAAA BBBB B010"],
    ["bn.xcmpxchg", "rD,rA,rB",	    "0x7 01 DD DDDA AAAA BBBB B011"],
    ["bn.max",	    "rD,rA,rB",	    "0x7 01 DD DDDA AAAA BBBB B100"],
    ["bn.min",	    "rD,rA,rB",	    "0x7 01 DD DDDA AAAA BBBB B101"],
    ["bn.lim",	    "rD,rA,rB",	    "0x7 01 DD DDDA AAAA BBBB B110"],
    ["bn.slls",	    "rD,rA,rB",	    "0x7 10 DD DDDA AAAA BBBB B-00"],
    ["bn.sllis",	"rD,rA,H",	    "0x7 10 DD DDDA AAAA HHHH H-01"],
    ["fn.ftoi.s",	"rD,rA",	    "0x7 11 10 --0A AAAA DDDD D000"],
    ["fn.itof.s",	"rD,rA",	    "0x7 11 10 --0A AAAA DDDD D001"],
    ["bw.sb",	    "h(rA),rB",	    "0x8 00 BB BBBA AAAA hhhh hhhh hhhh hhhh hhhh hhhh hhhh hhhh"],
    ["bw.lbz",	    "rD,h(rA)",	    "0x8 01 DD DDDA AAAA hhhh hhhh hhhh hhhh hhhh hhhh hhhh hhhh"],
    ["bw.sh",	    "i(rA),rB",	    "0x8 10 BB BBBA AAAA 0iii iiii iiii iiii iiii iiii iiii iiii"],
    ["bw.lhz",	    "rD,i(rA)",	    "0x8 10 DD DDDA AAAA 1iii iiii iiii iiii iiii iiii iiii iiii"],
    ["bw.sw",	    "w(rA),rB",	    "0x8 11 BB BBBA AAAA 00ww wwww wwww wwww wwww wwww wwww wwww"],
    ["bw.lwz",	    "rD,w(rA)",	    "0x8 11 DD DDDA AAAA 01ww wwww wwww wwww wwww wwww wwww wwww"],
    ["bw.lws",	    "rD,w(rA)",	    "0x8 11 DD DDDA AAAA 10ww wwww wwww wwww wwww wwww wwww wwww"],
    ["bw.sd",	    "v(rA),rB",	    "0x8 11 BB BBBA AAAA 110v vvvv vvvv vvvv vvvv vvvv vvvv vvvv"],
    ["bw.ld",	    "rD,v(rA)",	    "0x8 11 DD DDDA AAAA 111v vvvv vvvv vvvv vvvv vvvv vvvv vvvv"],
    ["bw.addi",	    "rD,rA,g",	    "0x9 00 DD DDDA AAAA gggg gggg gggg gggg gggg gggg gggg gggg"],
    ["bw.andi",	    "rD,rA,h",	    "0x9 01 DD DDDA AAAA hhhh hhhh hhhh hhhh hhhh hhhh hhhh hhhh"],
    ["bw.ori",	    "rD,rA,h",	    "0x9 10 DD DDDA AAAA hhhh hhhh hhhh hhhh hhhh hhhh hhhh hhhh"],
    ["bw.sfeqi",	"rA,g",		    "0x9 11 01 10-A AAAA gggg gggg gggg gggg gggg gggg gggg gggg"],
    ["bw.sfnei",	"rA,g",		    "0x9 11 01 11-A AAAA gggg gggg gggg gggg gggg gggg gggg gggg"],
    ["bw.sfgesi",	"rA,g",		    "0x9 11 10 00-A AAAA gggg gggg gggg gggg gggg gggg gggg gggg"],
    ["bw.sfgeui",	"rA,g",		    "0x9 11 10 01-A AAAA gggg gggg gggg gggg gggg gggg gggg gggg"],
    ["bw.sfgtsi",	"rA,g",		    "0x9 11 10 10-A AAAA gggg gggg gggg gggg gggg gggg gggg gggg"],
    ["bw.sfgtui",	"rA,g",		    "0x9 11 10 11-A AAAA gggg gggg gggg gggg gggg gggg gggg gggg"],
    ["bw.sflesi",	"rA,g",		    "0x9 11 11 00-A AAAA gggg gggg gggg gggg gggg gggg gggg gggg"],
    ["bw.sfleui",	"rA,g",		    "0x9 11 11 01-A AAAA gggg gggg gggg gggg gggg gggg gggg gggg"],
    ["bw.sfltsi",	"rA,g",		    "0x9 11 11 10-A AAAA gggg gggg gggg gggg gggg gggg gggg gggg"],
    ["bw.sfltui",	"rA,g",		    "0x9 11 11 11-A AAAA gggg gggg gggg gggg gggg gggg gggg gggg"],
    ["bw.beqi",	    "rB,I,u",	    "0xa 00 00 00II IIIB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu"],
    ["bw.bnei",	    "rB,I,u",	    "0xa 00 00 01II IIIB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu"],
    ["bw.bgesi",	"rB,I,u",	    "0xa 00 00 10II IIIB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu"],
    ["bw.bgtsi",	"rB,I,u",	    "0xa 00 00 11II IIIB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu"],
    ["bw.blesi",	"rB,I,u",	    "0xa 00 01 00II IIIB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu"],
    ["bw.bltsi",	"rB,I,u",	    "0xa 00 01 01II IIIB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu"],
    ["bw.bgeui",	"rB,I,u",	    "0xa 00 01 10II IIIB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu"],
    ["bw.bgtui",	"rB,I,u",	    "0xa 00 01 11II IIIB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu"],
    ["bw.bleui",	"rB,I,u",	    "0xa 00 10 00II IIIB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu"],
    ["bw.bltui",	"rB,I,u",	    "0xa 00 10 01II IIIB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu"],
    ["bw.beq",	    "rA,rB,u",	    "0xa 00 10 10AA AAAB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu"],
    ["bw.bne",	    "rA,rB,u",	    "0xa 00 10 11AA AAAB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu"],
    ["bw.bges",	    "rA,rB,u",	    "0xa 00 11 00AA AAAB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu"],
    ["bw.bgts",	    "rA,rB,u",	    "0xa 00 11 01AA AAAB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu"],
    ["bw.bgeu",	    "rA,rB,u",	    "0xa 00 11 10AA AAAB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu"],
    ["bw.bgtu",	    "rA,rB,u",	    "0xa 00 11 11AA AAAB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu"],
    ["bw.jal",	    "z",		    "0xa 01 00 00-- ---- zzzz zzzz zzzz zzzz zzzz zzzz zzzz zzzz"],
    ["bw.j",	    "z",		    "0xa 01 00 01-- ---- zzzz zzzz zzzz zzzz zzzz zzzz zzzz zzzz"],
    ["bw.bf",	    "z",		    "0xa 01 00 10-- ---- zzzz zzzz zzzz zzzz zzzz zzzz zzzz zzzz"],
    ["bw.bnf",	    "z",		    "0xa 01 00 11-- ---- zzzz zzzz zzzz zzzz zzzz zzzz zzzz zzzz"],
    ["bw.ja",	    "g",		    "0xa 01 01 00-- ---- gggg gggg gggg gggg gggg gggg gggg gggg"],
    ["bw.jma",	    "rD,z",		    "0xa 01 01 01DD DDD0 zzzz zzzz zzzz zzzz zzzz zzzz zzzz zzzz"],
    ["bw.jmal",	    "rD,z",		    "0xa 01 01 01DD DDD1 zzzz zzzz zzzz zzzz zzzz zzzz zzzz zzzz"],
    ["bw.lma",	    "rD,z",		    "0xa 01 01 10DD DDD0 zzzz zzzz zzzz zzzz zzzz zzzz zzzz zzzz"],
    ["bw.sma",	    "rB,z",		    "0xa 01 01 10BB BBB1 zzzz zzzz zzzz zzzz zzzz zzzz zzzz zzzz"],
    ["bw.casewi",	"rB,z",		    "0xa 01 01 11BB BBB0 zzzz zzzz zzzz zzzz zzzz zzzz zzzz zzzz"],
    ["fw.beq.s",	"rA,rB,u",	    "0xa 01 10 00AA AAAB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu"],
    ["fw.bne.s",	"rA,rB,u",	    "0xa 01 10 01AA AAAB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu"],
    ["fw.bge.s",	"rA,rB,u",	    "0xa 01 10 10AA AAAB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu"],
    ["fw.bgt.s",	"rA,rB,u",	    "0xa 01 10 11AA AAAB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu"],
    ["bw.mfspr",	"rD,rA,o",	    "0xa 10 DD DDDA AAAA oooo oooo oooo oooo oooo oooo ---- -000"],
    ["bw.mtspr",	"rA,rB,o",	    "0xa 10 BB BBBA AAAA oooo oooo oooo oooo oooo oooo ---- -001"],
    ["bw.addci",	"rD,rA,p",	    "0xa 10 DD DDDA AAAA pppp pppp pppp pppp pppp pppp ---- -010"],
    ["bw.divi",	    "rD,rA,p",	    "0xa 10 DD DDDA AAAA pppp pppp pppp pppp pppp pppp ---- -011"],
    ["bw.divui",	"rD,rA,o",	    "0xa 10 DD DDDA AAAA oooo oooo oooo oooo oooo oooo ---- -100"],
    ["bw.muli",	    "rD,rA,p",	    "0xa 10 DD DDDA AAAA pppp pppp pppp pppp pppp pppp ---- -101"],
    ["bw.xori",	    "rD,rA,p",	    "0xa 10 DD DDDA AAAA pppp pppp pppp pppp pppp pppp ---- -110"],
    ["bw.mulas",	"rD,rA,rB,H",	"0xa 11 DD DDDA AAAA BBBB BHHH HH-- ---- ---- ---- --00 0000"],
    ["bw.muluas",	"rD,rA,rB,H",	"0xa 11 DD DDDA AAAA BBBB BHHH HH-- ---- ---- ---- --00 0001"],
    ["bw.mulras",	"rD,rA,rB,H",	"0xa 11 DD DDDA AAAA BBBB BHHH HH-- ---- ---- ---- --00 0010"],
    ["bw.muluras",	"rD,rA,rB,H",	"0xa 11 DD DDDA AAAA BBBB BHHH HH-- ---- ---- ---- --00 0011"],
    ["bw.mulsu",	"rD,rA,rB",	    "0xa 11 DD DDDA AAAA BBBB B--- ---- ---- ---- ---- --00 0100"],
    ["bw.mulhsu",	"rD,rA,rB",	    "0xa 11 DD DDDA AAAA BBBB B--- ---- ---- ---- ---- --00 0101"],
    ["bw.mulhlsu",	"rD,rQ,rA,rB",	"0xa 11 DD DDDA AAAA BBBB BQQQ QQ-- ---- ---- ---- --00 0110"],                                                 
    ["bw.smultt",	"rD,rA,rB",	    "0xa 11 DD DDDA AAAA BBBB B--- ---- ---- ---- ---- --10 0000"],
    ["bw.smultb",	"rD,rA,rB",	    "0xa 11 DD DDDA AAAA BBBB B--- ---- ---- ---- ---- --10 0001"],
    ["bw.smulbb",	"rD,rA,rB",	    "0xa 11 DD DDDA AAAA BBBB B--- ---- ---- ---- ---- --10 0010"],
    ["bw.smulwb",	"rD,rA,rB",	    "0xa 11 DD DDDA AAAA BBBB B--- ---- ---- ---- ---- --10 0011"],
    ["bw.smulwt",	"rD,rA,rB",	    "0xa 11 DD DDDA AAAA BBBB B--- ---- ---- ---- ---- --10 0100"],
    ["bw.umultt",	"rD,rA,rB",	    "0xa 11 DD DDDA AAAA BBBB B--- ---- ---- ---- ---- --10 1000"],
    ["bw.umultb",	"rD,rA,rB",	    "0xa 11 DD DDDA AAAA BBBB B--- ---- ---- ---- ---- --10 1001"],
    ["bw.umulbb",	"rD,rA,rB",	    "0xa 11 DD DDDA AAAA BBBB B--- ---- ---- ---- ---- --10 1010"],
    ["bw.umulwb",	"rD,rA,rB",	    "0xa 11 DD DDDA AAAA BBBB B--- ---- ---- ---- ---- --10 1011"],
    ["bw.umulwt",	"rD,rA,rB",	    "0xa 11 DD DDDA AAAA BBBB B--- ---- ---- ---- ---- --10 1100"],
    ["bw.smadtt",	"rD,rA,rB,rR",	"0xa 11 DD DDDA AAAA BBBB BRRR RR-- ---- ---- ---- --11 0000"],
    ["bw.smadtb",	"rD,rA,rB,rR",	"0xa 11 DD DDDA AAAA BBBB BRRR RR-- ---- ---- ---- --11 0001"],
    ["bw.smadbb",	"rD,rA,rB,rR",	"0xa 11 DD DDDA AAAA BBBB BRRR RR-- ---- ---- ---- --11 0010"],
    ["bw.smadwb",	"rD,rA,rB,rR",	"0xa 11 DD DDDA AAAA BBBB BRRR RR-- ---- ---- ---- --11 0011"],
    ["bw.smadwt",	"rD,rA,rB,rR",	"0xa 11 DD DDDA AAAA BBBB BRRR RR-- ---- ---- ---- --11 0100"],
    ["bw.umadtt",	"rD,rA,rB,rR",	"0xa 11 DD DDDA AAAA BBBB BRRR RR-- ---- ---- ---- --11 1000"],
    ["bw.umadtb",	"rD,rA,rB,rR",	"0xa 11 DD DDDA AAAA BBBB BRRR RR-- ---- ---- ---- --11 1001"],
    ["bw.umadbb",	"rD,rA,rB,rR",	"0xa 11 DD DDDA AAAA BBBB BRRR RR-- ---- ---- ---- --11 1010"],
    ["bw.umadwb",	"rD,rA,rB,rR",	"0xa 11 DD DDDA AAAA BBBB BRRR RR-- ---- ---- ---- --11 1011"],
    ["bw.umadwt",	"rD,rA,rB,rR",	"0xa 11 DD DDDA AAAA BBBB BRRR RR-- ---- ---- ---- --11 1100"],
    ["bw.copdss",	"rD,rA,rB,y",	"0xb 00 DD DDDA AAAA BBBB Byyy yyyy yyyy yyyy yyyy yyyy yyyy"],
    ["bw.copd",	    "rD,g,H",	    "0xb 01 DD DDDH HHHH gggg gggg gggg gggg gggg gggg gggg gggg"],
    ["bw.cop",	    "g,x",		    "0xb 10 xx xxxx xxxx gggg gggg gggg gggg gggg gggg gggg gggg"],
    ["bg.sb",	    "Y(rA),rB",	    "0xc 00 BB BBBA AAAA YYYY YYYY YYYY YYYY"],
    ["bg.lbz",	    "rD,Y(rA)",	    "0xc 01 DD DDDA AAAA YYYY YYYY YYYY YYYY"],
    ["bg.sh",	    "X(rA),rB",	    "0xc 10 BB BBBA AAAA 0XXX XXXX XXXX XXXX"],
    ["bg.lhz",	    "rD,X(rA)",	    "0xc 10 DD DDDA AAAA 1XXX XXXX XXXX XXXX"],
    ["bg.sw",	    "W(rA),rB",	    "0xc 11 BB BBBA AAAA 00WW WWWW WWWW WWWW"],
    ["bg.lwz",	    "rD,W(rA)",	    "0xc 11 DD DDDA AAAA 01WW WWWW WWWW WWWW"],
    ["bg.lws",	    "rD,W(rA)",	    "0xc 11 DD DDDA AAAA 10WW WWWW WWWW WWWW"],
    ["bg.sd",	    "V(rA),rB",	    "0xc 11 BB BBBA AAAA 110V VVVV VVVV VVVV"],
    ["bg.ld",	    "rD,V(rA)",	    "0xc 11 DD DDDA AAAA 111V VVVV VVVV VVVV"],
    ["bg.beqi",	    "rB,I,U",	    "0xd 00 00 00II IIIB BBBB UUUU UUUU UUUU"],
    ["bg.bnei",	    "rB,I,U",	    "0xd 00 00 01II IIIB BBBB UUUU UUUU UUUU"],
    ["bg.bgesi",	"rB,I,U",	    "0xd 00 00 10II IIIB BBBB UUUU UUUU UUUU"],
    ["bg.bgtsi",	"rB,I,U",	    "0xd 00 00 11II IIIB BBBB UUUU UUUU UUUU"],
    ["bg.blesi",	"rB,I,U",	    "0xd 00 01 00II IIIB BBBB UUUU UUUU UUUU"],
    ["bg.bltsi",	"rB,I,U",	    "0xd 00 01 01II IIIB BBBB UUUU UUUU UUUU"],
    ["bg.bgeui",	"rB,I,U",	    "0xd 00 01 10II IIIB BBBB UUUU UUUU UUUU"],
    ["bg.bgtui",	"rB,I,U",	    "0xd 00 01 11II IIIB BBBB UUUU UUUU UUUU"],
    ["bg.bleui",	"rB,I,U",	    "0xd 00 10 00II IIIB BBBB UUUU UUUU UUUU"],
    ["bg.bltui",	"rB,I,U",	    "0xd 00 10 01II IIIB BBBB UUUU UUUU UUUU"],
    ["bg.beq",	    "rA,rB,U",	    "0xd 00 10 10AA AAAB BBBB UUUU UUUU UUUU"],
    ["bg.bne",	    "rA,rB,U",	    "0xd 00 10 11AA AAAB BBBB UUUU UUUU UUUU"],
    ["bg.bges",	    "rA,rB,U",	    "0xd 00 11 00AA AAAB BBBB UUUU UUUU UUUU"],
    ["bg.bgts",	    "rA,rB,U",	    "0xd 00 11 01AA AAAB BBBB UUUU UUUU UUUU"],
    ["bg.bgeu",	    "rA,rB,U",	    "0xd 00 11 10AA AAAB BBBB UUUU UUUU UUUU"],
    ["bg.bgtu",	    "rA,rB,U",	    "0xd 00 11 11AA AAAB BBBB UUUU UUUU UUUU"],
    ["bg.jal",	    "t",		    "0xd 01 00 tttt tttt tttt tttt tttt tttt"],
    ["bg.j",	    "t",		    "0xd 01 01 tttt tttt tttt tttt tttt tttt"],
    ["bg.bf",	    "t",		    "0xd 01 10 tttt tttt tttt tttt tttt tttt"],
    ["bg.bnf",	    "t",		    "0xd 01 11 tttt tttt tttt tttt tttt tttt"],
    ["bg.addi",	    "rD,rA,Y",	    "0xd 10 DD DDDA AAAA YYYY YYYY YYYY YYYY"],
    ["fg.beq.s",	"rA,rB,U",	    "0xd 11 00 00AA AAAB BBBB UUUU UUUU UUUU"],
    ["fg.bne.s",	"rA,rB,U",	    "0xd 11 00 01AA AAAB BBBB UUUU UUUU UUUU"],
    ["fg.bge.s",	"rA,rB,U",	    "0xd 11 00 10AA AAAB BBBB UUUU UUUU UUUU"],
    ["fg.bgt.s",	"rA,rB,U",	    "0xd 11 00 11AA AAAB BBBB UUUU UUUU UUUU"]
]

# Extract the immediate from an instruction given the instruction and the mask
def extract_immediate(instruction, mask):
    shift         = utils.get_first_one_pos(mask)

    #print("Extract immediate")
    #print(instruction)
    #print(mask)
    #print(shift)

    return (instruction & mask) >> shift

# Extract the register from an instruction given the instruction and the mask
def extract_register(instruction, mask):
    register_number = extract_immediate(instruction, mask)

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
    #print("Data length: " + str(len(data)))

    instruction      = None
    instruction_len  = 0
    instruction_data = None

    # Limit input to 6 bytes
    #data = data[:6]
    #data_int = int.from_bytes(data, byteorder="little")

    if len(data) < 1:
        return None, 0, instruction_data

    for tested_instruction_len in range(3, 7):
        data_tmp = data[:tested_instruction_len]
        data_int = int.from_bytes(data_tmp, byteorder="big")

        for i in range(0, len(beyond_opcodes)):
            instructionOperands     = []

            operand_name            = beyond_opcodes[i][OPCODE_DEF_INDEX_OPCODE_NAME]
            instruction_definition  = beyond_opcodes[i][OPCODE_DEF_INDEX_OPERAND_DEFINITIONS]
            opcode_mask_0           = beyond_opcodes[i][OPCODE_DEF_INDEX_OPCODE_MASK_0]
            opcode_mask_1           = beyond_opcodes[i][OPCODE_DEF_INDEX_OPCODE_MASK_1]
            opcodes                 = beyond_opcodes[i][OPCODE_DEF_INDEX_OPERAND_MASKS:]

            # Test if instruction len matches
            if int(len(instruction_definition) / 8) != tested_instruction_len:
                break

            # Check if the opcode matches
            #if len(data)*8 != len(instruction_definition):
            #    continue
            
            # Check 0s
            if not (~data_int & opcode_mask_0 == opcode_mask_0):
                continue
            # Check 1s
            if not (data_int & opcode_mask_1 == opcode_mask_1):
                continue

            #print("Disassemling for instruction: " + operand_name)

            #for opcode in opcodes:
                #print(opcode)

            # Iterate over all opcodes
            for opcode in opcodes:
                if  opcode[0] == OperandType.Immediate:
                    immediate_mask = opcode[1][0]

                    #print("Immediate mask")
                    #print(immediate_mask)

                    immediate = extract_immediate(data_int, immediate_mask)

                    instructionOperands.append(ImmediateOperand(immediate))
                elif  opcode[0] == OperandType.Register:
                    register_mask = opcode[1][0]     

                    #print("Register mask")
                    #print(register_mask)
                    #print(type(register_mask))

                    register = extract_register(data_int, register_mask)

                    instructionOperands.append(RegisterOperand(register))
                elif  opcode[0] == OperandType.Memory:
                    register_mask  = opcode[1][0]
                    immediate_mask = opcode[1][1]

                    immediate = extract_immediate(data_int, immediate_mask)
                    register = extract_register(data_int, register_mask)

                    instructionOperands.append(MemoryOperand([ImmediateOperand(immediate), RegisterOperand(register)]))

            #print("Parsed instruction operands: ")
            #for op in instructionOperands:
                #print(str(op))

            instruction_len = int(len(instruction_definition) / 8)
            instruction = Instruction(operand_name, instructionOperands)

            #print(str(instruction))

            break

    #print(instruction)

    if instruction.opcode == "bt.j":
        instruction_data = [BranchType.UnconditionalBranch, instruction.operands[0].immediate + addr]

    if instruction.opcode == "bn.j":
        instruction_data = [BranchType.UnconditionalBranch, instruction.operands[0].immediate + addr]

    if instruction.opcode == "bn.bf":
        instruction_data = [BranchType.UnconditionalBranch, instruction.operands[0].immediate + addr]

    if instruction.opcode == "bn.bnf":
        instruction_data = [BranchType.UnconditionalBranch, instruction.operands[0].immediate + addr]

    if instruction.opcode == "bn.bo":
        instruction_data = [BranchType.UnconditionalBranch, instruction.operands[0].immediate + addr]
    
    if instruction.opcode == "bn.bno":
        instruction_data = [BranchType.UnconditionalBranch, instruction.operands[0].immediate + addr]

    if instruction.opcode == "bn.bc":
        instruction_data = [BranchType.UnconditionalBranch, instruction.operands[0].immediate + addr]

    if instruction.opcode == "bn.bnc":
        instruction_data = [BranchType.UnconditionalBranch, instruction.operands[0].immediate + addr]

    if instruction.opcode == "bn.jalr":
        instruction_data = [BranchType.IndirectBranch, instruction.operands[0].immediate + addr]

    if instruction.opcode == "bn.jr":
        instruction_data = [BranchType.IndirectBranch, instruction.operands[0].immediate + addr]

    if instruction.opcode == "bn.jal":
        instruction_data = [BranchType.CallDestination, instruction.operands[0].immediate + addr]

    if instruction.opcode == "bw.jal":
        instruction_data = [BranchType.CallDestination, instruction.operands[0].immediate + addr]

    if instruction.opcode == "bw.j":
        instruction_data = [BranchType.UnconditionalBranch, instruction.operands[0].immediate + addr]

    if instruction.opcode == "bw.bf":
        instruction_data = [BranchType.UnconditionalBranch, instruction.operands[0].immediate + addr]

    if instruction.opcode == "bw.bnf":
        instruction_data = [BranchType.UnconditionalBranch, instruction.operands[0].immediate + addr]

    #if instruction.opcode == "bw.ja":
    #    instruction_data = [BranchType.UnconditionalBranch, instruction.operands[0].immediate + addr]

    if instruction.opcode == "bg.jal":
        instruction_data = [BranchType.CallDestination, instruction.operands[0].immediate + addr]

    if instruction.opcode == "bg.j":
        instruction_data = [BranchType.UnconditionalBranch, instruction.operands[0].immediate + addr]

    if instruction.opcode == "bg.bf":
        instruction_data = [BranchType.UnconditionalBranch, instruction.operands[0].immediate + addr]

    if instruction.opcode == "bg.bnf":
        instruction_data = [BranchType.UnconditionalBranch, instruction.operands[0].immediate + addr]

    if instruction.opcode == "bg.return":
        instruction_data = [BranchType.FunctionReturn, 0]

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

        #print("INSTRUCTION: " + operand_name)

        # 1)
        # Replace the "0x..." opcode definition at the beginning of the strings
        # with their binary representation
        beyond_opcodes[i][OPCODE_DEF_INDEX_OPERAND_DEFINITIONS] = beyond_opcodes[i][OPCODE_DEF_INDEX_OPERAND_DEFINITIONS].replace(' ', '')
        format_str                                              = "{:0" + str(OPCODE_LENGTH) + "b}"
        beyond_opcodes[i][OPCODE_DEF_INDEX_OPERAND_DEFINITIONS] = format_str.format(int(beyond_opcodes[i][OPCODE_DEF_INDEX_OPERAND_DEFINITIONS][:3], 16)) + beyond_opcodes[i][OPCODE_DEF_INDEX_OPERAND_DEFINITIONS][3:]
        instruction_definition                                  = beyond_opcodes[i][OPCODE_DEF_INDEX_OPERAND_DEFINITIONS]
        #print(instruction_definition)

        # 2)
        # Append a quick opcode check mask. This mask contains only the bits needed
        # for identifying the instruction type.
        operand_mask_0, operand_mask_1 = parse_opcode(instruction_definition)
        beyond_opcodes[i].append(operand_mask_0)
        beyond_opcodes[i].append(operand_mask_1)
        #print("Opcode mask 0: " + bin(operand_mask_0))
        #print("Opcode mask 1: " + bin(operand_mask_1))

        # 3)
        # For every opcode, compute the mask and store it in the opcode
        # definition array
        operands                = operand_definition.split(",")

        for operand in operands:
            # Parse the provided operand
            parsed_operand = parse_operand(operand, instruction_definition)
            beyond_opcodes[i].append(parsed_operand)