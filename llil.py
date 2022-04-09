from binaryninja.lowlevelil import LowLevelILLabel, ILRegister

import beyond.disasm as disasm

def unimplemented(il, inst):
    return il.unimplemented()

def op_as_il(il, op):
    if type(op) is disasm.Register:
        return il.reg(4, op.register)
    if type(op) is disasm.Immediate:
        return il.const(4, op.immediate)

#
# Arithmetic Expressions
#

def arith(il, inst, expr, src_dst):
    return il.set_reg(
        4,
        op_as_il(il, src_dst[0]),
        expr(
            src_dst[1:]
        )
    )

def lift_bt_movi(il, inst):
    return arith(il, inst,
        lambda src : op_as_il(il, src[0]),
        [inst.operand[0].register, inst.operand[1].immediate])

def lift_bt_addi(il, inst):
    return arith(il, inst,
        lambda src : il.add(4, op_as_il(il, src[0]), op_as_il(il, src[1]))
        [inst.operand[0].register, inst.operand[1].immediate])

def lift_bn_addi(il, inst):
    return arith(il, inst,
        lambda src : il.add(4, op_as_il(il, src[0]), op_as_il(il, src[1]))
        [inst.operand[0].register, inst.operand[1].register, inst.operand[2].immediate])

def lift_bt_mov(il, inst):
    return arith(il, inst,
        lambda src : op_as_il(il, src[0]),
        [inst.operand[0].register, inst.operand[1].register])

def lift_bt_add(il, inst):
    return arith(il, inst,
        lambda src : il.add(4, op_as_il(il, src[0]), op_as_il(il, src[1]))
        [inst.operand[0].register, inst.operand[1].register])

def lift_bn_andi(il, inst):
    return arith(il, inst,
        lambda src : il.and_expr(4, op_as_il(il, src[0]), op_as_il(il, src[1]))
        [inst.operand[0].register, inst.operand[1].register, inst.operand[2].immediate])

def lift_bn_ori(il, inst):
    return arith(il, inst,
        lambda src : il.or_expr(4, op_as_il(il, src[0]), op_as_il(il, src[1]))
        [inst.operand[0].register, inst.operand[1].register, inst.operand[2].immediate])

def lift_bn_and(il, inst):
    return arith(il, inst,
        lambda src : il.and_expr(4, op_as_il(il, src[0]), op_as_il(il, src[1]))
        [inst.operand[0].register, inst.operand[1].register, inst.operand[2].register])

def lift_bn_or(il, inst):
    return arith(il, inst,
        lambda src : il.or_expr(4, op_as_il(il, src[0]), op_as_il(il, src[1]))
        [inst.operand[0].register, inst.operand[1].register, inst.operand[2].register])

def lift_bn_xor(il, inst):
    return arith(il, inst,
        lambda src : il.xor_expr(4, op_as_il(il, src[0]), op_as_il(il, src[1]))
        [inst.operand[0].register, inst.operand[1].register, inst.operand[2].register])

#
# Control Flow Expressions
#


#
# Memory Load/Store Expressions
#

