from binaryninja.architecture import Architecture
from binaryninja.function import RegisterInfo, InstructionInfo

from binaryninja.enums import InstructionTextTokenType
from binaryninja.function import InstructionTextToken

import beyond.disasm as disasm

class Beyond2(Architecture):
    name = "beyond2"
    address_size = 4
    default_int_size = 4
    instr_alignment = 1
    max_inst_length = 6

    regs = {
        "r0" : RegisterInfo("r0", address_size),
        "r1" : RegisterInfo("r1", address_size),
        "r2" : RegisterInfo("r2", address_size),
        "r3" : RegisterInfo("r3", address_size),
        "r4" : RegisterInfo("r4", address_size),
        "r5" : RegisterInfo("r5", address_size),
        "r6" : RegisterInfo("r6", address_size),
        "r7" : RegisterInfo("r7", address_size),
        "r8" : RegisterInfo("r8", address_size),
        "r9" : RegisterInfo("r9", address_size),
        "r10" : RegisterInfo("r10", address_size),
        "r11" : RegisterInfo("r11", address_size),
        "r12" : RegisterInfo("r12", address_size),
        "r13" : RegisterInfo("r13", address_size),
        "r14" : RegisterInfo("r14", address_size),
        "r15" : RegisterInfo("r15", address_size),
        "r16" : RegisterInfo("r16", address_size),
        "r17" : RegisterInfo("r17", address_size),
        "r18" : RegisterInfo("r18", address_size),
        "r19" : RegisterInfo("r19", address_size),
        "r20" : RegisterInfo("r20", address_size),
        "r21" : RegisterInfo("r21", address_size),
        "r22" : RegisterInfo("r22", address_size),
        "r23" : RegisterInfo("r23", address_size),
        "r24" : RegisterInfo("r24", address_size),
        "r25" : RegisterInfo("r25", address_size),
        "r26" : RegisterInfo("r26", address_size),
        "r27" : RegisterInfo("r27", address_size),
        "r28" : RegisterInfo("r28", address_size),
        "r29" : RegisterInfo("r29", address_size),
        "r30" : RegisterInfo("r30", address_size),
        "r31" : RegisterInfo("r31", address_size),
    }

    flags = ["F", "OV", "C"]

    stack_pointer = "r1"

    def get_instruction_info(self, data, addr):
        result = None

        _, instruction_len, instruction_data = disasm.disassemble(data, addr)
        if instruction_len == 0:
            #print("result.length == 0")
            return None

        result = InstructionInfo()
        result.length = instruction_len

        if instruction_data is not None:
            if len(instruction_data) == 1:
                #print("Adding indirect branch")
                result.add_branch(instruction_data[0])
            if len(instruction_data) == 2:
                #print("Adding branch to: " + hex(instruction_data[1]))
                result.add_branch(instruction_data[0], instruction_data[1])
            if len(instruction_data) == 4:
                #print("Adding true branch to: " + hex(instruction_data[1]))
                result.add_branch(instruction_data[0], instruction_data[1])
                #print("Adding false branch to: " + hex(instruction_data[3]))
                result.add_branch(instruction_data[2], instruction_data[3])

        #print(hex(addr) + " get_instruction_info: " + str(result.length))

        return result

    def get_instruction_text(self, data, addr):
        #print("get_instruction_text 1")

        instruction, instruction_len, _ = disasm.disassemble(data, addr)

        if instruction is None:
            return None, 0

        tokens = instruction.get_instruction_text()
        if instruction_len == 0:
            #print("instruction_len == 0")
            return None, 0

        return tokens, instruction_len

    def get_instruction_low_level_il(self, data, addr, il):
        expr, instruction_len = disasm.instruction_to_llil(data, addr, il)

        if expr is not None:
            il.append(expr)

        return instruction_len

def register_arch():
    Beyond2.register()
    disasm.init_disassembler()