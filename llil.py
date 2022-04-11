from binaryninja import Architecture
from binaryninja.lowlevelil import LowLevelILLabel, ILRegister

import beyond.disasm as disasm

def unimplemented(il, inst):
    return il.unimplemented()

def op_as_il(il, op):
    if type(op) is disasm.Register:
        if op is disasm.Register.r0:
            return il.const(4, 0)
        else:
            return il.reg(4, op)
    else:
        print(type(op))
        return il.const(4, op)

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
        [inst.operands[0].register, inst.operands[1].immediate])

def lift_bt_addi(il, inst):
    return arith(il, inst,
        lambda src : il.add(4, op_as_il(il, src[0]), op_as_il(il, src[1])),
        [inst.operands[0].register, inst.operands[1].immediate])

def lift_bn_addi(il, inst):
    return arith(il, inst,
        lambda src : il.add(4, op_as_il(il, src[0]), op_as_il(il, src[1])),
        [inst.operands[0].register, inst.operands[1].register, inst.operands[2].immediate])

def lift_bt_mov(il, inst):
    return arith(il, inst,
        lambda src : op_as_il(il, src[0]),
        [inst.operands[0].register, inst.operands[1].register])

def lift_bt_add(il, inst):
    return arith(il, inst,
        lambda src : il.add(4, op_as_il(il, src[0]), op_as_il(il, src[1])),
        [inst.operands[0].register, inst.operands[1].register])

def lift_bn_andi(il, inst):
    return arith(il, inst,
        lambda src : il.and_expr(4, op_as_il(il, src[0]), op_as_il(il, src[1])),
        [inst.operands[0].register, inst.operands[1].register, inst.operands[2].immediate])

def lift_bn_ori(il, inst):
    return arith(il, inst,
        lambda src : il.or_expr(4, op_as_il(il, src[0]), op_as_il(il, src[1])),
        [inst.operands[0].register, inst.operands[1].register, inst.operands[2].immediate])

def lift_bn_and(il, inst):
    return arith(il, inst,
        lambda src : il.and_expr(4, op_as_il(il, src[0]), op_as_il(il, src[1])),
        [inst.operands[0].register, inst.operands[1].register, inst.operands[2].register])

def lift_bn_or(il, inst):
    return arith(il, inst,
        lambda src : il.or_expr(4, op_as_il(il, src[0]), op_as_il(il, src[1])),
        [inst.operands[0].register, inst.operands[1].register, inst.operands[2].register])

def lift_bn_xor(il, inst):
    return arith(il, inst,
        lambda src : il.xor_expr(4, op_as_il(il, src[0]), op_as_il(il, src[1])),
        [inst.operands[0].register, inst.operands[1].register, inst.operands[2].register])


#
# Conditional Expressions
#

def cond(il, inst, expr, src):
    return il.set_flag(
        "F",
        expr(src)
    )

def lift_bn_sfeqi(il, inst):
    return cond(il, inst,
        lambda src : il.compare_equal(4, op_as_il(il, src[0]), op_as_il(il, src[1])),
        [inst.operands[0].register, inst.operands[1].immediate])

def lift_bn_sfnei(il, inst):
    return cond(il, inst,
        lambda src : il.compare_not_equal(4, op_as_il(il, src[0]), op_as_il(il, src[1])),
        [inst.operands[0].register, inst.operands[1].immediate])

def lift_bn_sfgesi(il, inst):
    return cond(il, inst,
        lambda src : il.compare_signed_greater_equal(4, op_as_il(il, src[0]), op_as_il(il, src[1])),
        [inst.operands[0].register, inst.operands[1].immediate])

def lift_bn_sfgeui(il, inst):
    return lift_bn_sfgesi(il, inst)

def lift_bn_sfgtsi(il, inst):
    return cond(il, inst,
        lambda src : il.compare_signed_greater_than(4, op_as_il(il, src[0]), op_as_il(il, src[1])),
        [inst.operands[0].register, inst.operands[1].immediate])

def lift_bn_sfgtui(il, inst):
    return lift_bn_sfgesi(il, inst)

def lift_bn_sflesi(il, inst):
    return cond(il, inst,
        lambda src : il.compare_signed_less_equal(4, op_as_il(il, src[0]), op_as_il(il, src[1])),
        [inst.operands[0].register, inst.operands[1].immediate])

def lift_bn_sfleui(il, inst):
    return lift_bn_sfgesi(il, inst)

def lift_bn_sfltsi(il, inst):
    return cond(il, inst,
        lambda src : il.compare_signed_less_than(4, op_as_il(il, src[0]), op_as_il(il, src[1])),
        [inst.operands[0].register, inst.operands[1].immediate])

def lift_bn_sfltui(il, inst):
    return lift_bn_sfgesi(il, inst)

def lift_bn_sfeq(il, inst):
    return cond(il, inst,
        lambda src : il.compare_equal(4, op_as_il(il, src[0]), op_as_il(il, src[1])),
        [inst.operands[0].register, inst.operands[1].register])

def lift_bn_sfne(il, inst):
    return cond(il, inst,
        lambda src : il.compare_not_equal(4, op_as_il(il, src[0]), op_as_il(il, src[1])),
        [inst.operands[0].register, inst.operands[1].register])

def lift_bn_sfges(il, inst):
    return cond(il, inst,
        lambda src : il.compare_signed_greater_equal(4, op_as_il(il, src[0]), op_as_il(il, src[1])),
        [inst.operands[0].register, inst.operands[1].register])

def lift_bn_sfgeu(il, inst):
    return lift_bn_sfgesi(il, inst)

def lift_bn_sfgts(il, inst):
    return cond(il, inst,
        lambda src : il.compare_signed_greater_than(4, op_as_il(il, src[0]), op_as_il(il, src[1])),
        [inst.operands[0].register, inst.operands[1].register])

def lift_bn_sfgtu(il, inst):
    return lift_bn_sfgesi(il, inst)

# TODO: Don't need this function
def lift_bn_sfles(il, inst):
    return cond(il, inst,
        lambda src : il.compare_signed_less_equal(4, op_as_il(il, src[0]), op_as_il(il, src[1])),
        [inst.operands[0].register, inst.operands[1].register])

# TODO: Don't need this function
def lift_bn_sfleu(il, inst):
    return lift_bn_sfgesi(il, inst)

# TODO: Don't need this function
def lift_bn_sflts(il, inst):
    return cond(il, inst,
        lambda src : il.compare_signed_less_than(4, op_as_il(il, src[0]), op_as_il(il, src[1])),
        [inst.operands[0].register, inst.operands[1].register])

# TODO: Don't need this function
def lift_bn_sfltu(il, inst):
    return lift_bn_sfgesi(il, inst)


#
# Control Flow Expressions
#

def cond_jump(il, inst, expr):
    jump_target = op_as_il(il, inst.operands[2].immediate)

    t = il.get_label_for_address(Architecture["beyond2"], jump_target)
    if t is None:
        t = LowLevelILLabel()

    f = il.get_label_for_address(Architecture["beyond2"], il.current_address + 4) # TODO: Correct instruction size
    if f is None:
        f = LowLevelILLabel()

    il.append(
        il.if_expr(
            expr, 
            t, 
            f
        )
    )
    il.mark_label(t)
    il.append(
        il.jump(
            jump_target
        )
    )
    il.mark_label(f)

# Flag-based instructions

def lift_bn_bf(il, inst):
    cond_jump(il, inst, il.flag("F"))
    return None

def lift_bn_bnf(il, inst):
    cond_jump(il, inst, il.not_expr(4, il.flag("F")))
    return None

def lift_bn_bo(il, inst):
    cond_jump(il, inst, il.flag("OV"))
    return None

def lift_bn_bno(il, inst):
    cond_jump(il, inst, il.not_expr(4, il.flag("OV")))
    return None

def lift_bn_bc(il, inst):
    cond_jump(il, inst, il.flag("C"))
    return None

def lift_bn_bnc(il, inst):
    cond_jump(il, inst, il.not_expr(4, il.flag("C")))
    return None

def lift_bn_j(il, inst):
    j_label = il.get_label_for_address(Architecture["beyond2"], op_as_il(il, inst.operands[0].immediate))
    
    if j_label is not None:
        expr = il.goto(j_label)
    else:
        expr = il.jump(op_as_il(il, inst.operands[0].immediate))
    
    return expr

# Comparison-based instruction

def lift_bn_beqi(il, inst):
    cond_jump(il, inst, 
        il.compare_equal(
            4,
            op_as_il(il, inst.operands[0].register),
            op_as_il(il, inst.operands[1].immediate)
        )
    )

def lift_bn_bnei(il, inst):
    cond_jump(il, inst, 
        il.compare_not_equal(
            4,
            op_as_il(il, inst.operands[0].register),
            op_as_il(il, inst.operands[1].immediate)
        )
    )

def lift_bn_bgesi(il, inst):
    cond_jump(il, inst, 
        il.compare_greater_equal(
            4,
            op_as_il(il, inst.operands[0].register),
            op_as_il(il, inst.operands[1].immediate)
        )
    )

def lift_bn_bgtsi(il, inst):
    cond_jump(il, inst, 
        il.compare_greater_than(
            4,
            op_as_il(il, inst.operands[0].register),
            op_as_il(il, inst.operands[1].immediate)
        )
    )

def lift_bn_blesi(il, inst):
    cond_jump(il, inst, 
        il.compare_less_equal(
            4,
            op_as_il(il, inst.operands[0].register),
            op_as_il(il, inst.operands[1].immediate)
        )
    )

def lift_bn_bltsi(il, inst):
    cond_jump(il, inst, 
        il.compare_less_than(
            4,
            op_as_il(il, inst.operands[0].register),
            op_as_il(il, inst.operands[1].immediate)
        )
    )

def lift_bw_beq(il, inst):
    cond_jump(il, inst, 
        il.compare_equal(
            4,
            op_as_il(il, inst.operands[0].register),
            op_as_il(il, inst.operands[1].register)
        )
    )

def lift_bw_bne(il, inst):
    cond_jump(il, inst, 
        il.compare_not_equal(
            4,
            op_as_il(il, inst.operands[0].register),
            op_as_il(il, inst.operands[1].register)
        )
    )

def lift_bw_bges(il, inst):
    cond_jump(il, inst, 
        il.compare_greater_equal(
            4,
            op_as_il(il, inst.operands[0].register),
            op_as_il(il, inst.operands[1].register)
        )
    )

def lift_bw_bgts(il, inst):
    cond_jump(il, inst, 
        il.compare_greater_than(
            4,
            op_as_il(il, inst.operands[0].register),
            op_as_il(il, inst.operands[1].register)
        )
    )

#
# Memory Load/Store Expressions
#

def store(il, size, src_dst):
    return il.store(
        size,
        mem_operand(il,src_dst[0]),
        op_as_il(il, src_dst[1])
    )

def load(il, size, src_dst, sign_extend):
    if sign_extend:
        return il.set_reg(
                4,
                il.sign_extend(
                    4,
                    il.load(
                        size,
                        mem_operand(il, src_dst[1])
                    )
                ),
                op_as_il(il, src_dst[0])
            )
    else:
        return il.set_reg(
                4,
                il.zero_extend(
                    4,
                    il.load(
                        size,
                        mem_operand(il, src_dst[1])
                    )
                ),
                op_as_il(il, src_dst[0])
            )

def mem_operand(il, mem_op):
    return il.add(
        4,
        op_as_il(il, mem_op.operands[0].immediate),
        op_as_il(il, mem_op.operands[1].register)
    )

# Store instructions

def lift_bn_sb(il, inst):
    return store(il, 1, [inst.operands[0], inst.operands[1].register])

def lift_bn_sh(il, inst):
    return store(il, 2, [inst.operands[0], inst.operands[1].register])

def lift_bn_sw(il, inst):
    return store(il, 4, [inst.operands[0], inst.operands[1].register])

def lift_bn_sd(il, inst):
    return store(il, 8, [inst.operands[0], inst.operands[1].register])

# Load instructions
def lift_bn_lbz(il, inst):
    return load(il, 1, [inst.operands[0].register, inst.operands[1]], False)

def lift_bn_lhz(il, inst):
    return load(il, 2, [inst.operands[0].register, inst.operands[1]], False)

def lift_bn_lwz(il, inst):
    return load(il, 4, [inst.operands[0].register, inst.operands[1]], False)

def lift_bn_lws(il, inst):
    return load(il, 4, [inst.operands[0].register, inst.operands[1]], False)

def lift_bn_ld(il, inst):
    return load(il, 8, [inst.operands[0].register, inst.operands[1]], False)