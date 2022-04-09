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
        "r15" : RegisterInfo("r15", address_size)
    }

    stack_pointer = "r1"

    def get_instruction_info(self, data, addr):
        result = None

        #try:
        _, instruction_len, instruction_data = disasm.disassemble(data, addr)
        if instruction_len == 0:
            print("result.length == 0")
            return None

        result = InstructionInfo()
        result.length = instruction_len

        if instruction_data is not None:
            if len(instruction_data) == 2:
                print("Adding branch to: " + hex(instruction_data[1]))
                result.add_branch(instruction_data[0], instruction_data[1])
            if len(instruction_data) == 4:
                print("Adding true branch to: " + hex(instruction_data[1]))
                result.add_branch(instruction_data[0], instruction_data[1])
                print("Adding false branch to: " + hex(instruction_data[3]))
                result.add_branch(instruction_data[2], instruction_data[3])
        #except Exception as e:
        #    print(e)
        #    return None

        print(hex(addr) + " get_instruction_info: " + str(result.length))

        return result

    def get_instruction_text(self, data, addr):
        print("get_instruction_text 1")

        #try:
        instruction, instruction_len, _ = disasm.disassemble(data, addr)

        if instruction is None:
            return None, 0

        tokens = instruction.get_instruction_text()
        if instruction_len == 0:
            print("instruction_len == 0")
            return None, 0
        #except Exception as e:
        #    print(e)
        #    return None

        print("get_instruction_text 2")
        #print(tokens)
        #print(instruction_len)

        return tokens, instruction_len

    def get_instruction_low_level_il(self, data, addr, il):
        return None

def register_arch():
    Beyond2.register()
    disasm.init_disassembler()