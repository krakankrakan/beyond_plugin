from binaryninja.lowlevelil import LowLevelILLabel, ILRegister

def unimplemented(il):
    il.append(
        il.unimplemented()
    )

def lift_bt_movi(self, il, op, imm):
    unimplemented(il)
