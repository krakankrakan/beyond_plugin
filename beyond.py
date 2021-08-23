from binaryninja.architecture import Architecture
from binaryninja.function import RegisterInfo, InstructionInfo


from binaryninja.enums import InstructionTextTokenType
from binaryninja.function import InstructionTextToken




import beyond_isa.disasm as disasm

class Beyond2(Architecture):
    name = "beyond2"
    address_size = 4
    default_int_size = 2
    instr_alignment = 1
    max_inst_length = 6

    regs = {
        "r0" : RegisterInfo("r0", 4),
        "r1" : RegisterInfo("r1", 4),
        "r2" : RegisterInfo("r2", 4),
        "r3" : RegisterInfo("r3", 4),
        "r4" : RegisterInfo("r4", 4),
        "r5" : RegisterInfo("r5", 4),
        "r6" : RegisterInfo("r6", 4),
        "r7" : RegisterInfo("r7", 4),
        "r8" : RegisterInfo("r8", 4),
        "r9" : RegisterInfo("r9", 4),
        "r10" : RegisterInfo("r10", 4),
        "r11" : RegisterInfo("r11", 4),
        "r12" : RegisterInfo("r12", 4),
        "r13" : RegisterInfo("r13", 4),
        "r14" : RegisterInfo("r14", 4),
        "r15" : RegisterInfo("r15", 4)
    }

    stack_pointer = "r1"

    def get_instruction_info(self, data, addr):
        result = InstructionInfo()

        try:
            _, instruction_len, instruction_data = disasm.disassemble(data, addr)
            result.length = instruction_len
            if result.length == 0:
                return None
            if instruction_data != None:
                result.add_branch(instruction_data[0], instruction_data[1])
        except:
            return None

        #print(hex(addr) + " get_instruction_info: " + str(instruction_len))

        return result

    def get_instruction_text(self, data, addr):
        try:
            instruction, instruction_len, _ = disasm.disassemble(data, addr)
            tokens = instruction.get_instruction_text()
            if instruction_len == 0:
                return None
        except:
            return None

        print("get_instruction_text")
        #print(tokens)
        #print(instruction_len)

        return tokens, instruction_len

    def get_instruction_low_level_il(self, data, addr, il):
        return None

def register_arch():
    Beyond2.register()
    disasm.init_disassembler()