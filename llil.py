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
        #print(type(op))
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
        [inst.operands[0].register, inst.operands[0].register, inst.operands[1].immediate])

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
        [inst.operands[0].register, inst.operands[0].register, inst.operands[1].register])

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

def lift_bn_sub(il, inst):
    return arith(il, inst,
        lambda src : il.sub(4, op_as_il(il, src[0]), op_as_il(il, src[1])),
        [inst.operands[0].register, inst.operands[1].register, inst.operands[2].register])

def lift_bn_or(il, inst):
    return arith(il, inst,
        lambda src : il.or_expr(4, op_as_il(il, src[0]), op_as_il(il, src[1])),
        [inst.operands[0].register, inst.operands[1].register, inst.operands[2].register])

def lift_bn_xor(il, inst):
    return arith(il, inst,
        lambda src : il.xor_expr(4, op_as_il(il, src[0]), op_as_il(il, src[1])),
        [inst.operands[0].register, inst.operands[1].register, inst.operands[2].register])

def lift_bn_nand(il, inst):
    return arith(il, inst,
        lambda src : il.not_expr(4, il.and_expr(4, op_as_il(il, src[0]), op_as_il(il, src[1]))),
        [inst.operands[0].register, inst.operands[1].register, inst.operands[2].register])

def lift_bn_extbz(il, inst):
    return arith(il, inst,
        lambda src : il.zero_extend(4, il.reg(1, src[0])),
        [inst.operands[0].register, inst.operands[1].register])

def lift_bn_extbs(il, inst):
    return arith(il, inst,
        lambda src : il.sign_extend(4, il.reg(1, src[0])),
        [inst.operands[0].register, inst.operands[1].register])

def lift_bn_exthz(il, inst):
    return arith(il, inst,
        lambda src : il.zero_extend(4, il.reg(2, src[0])),
        [inst.operands[0].register, inst.operands[1].register])

def lift_bn_exths(il, inst):
    return arith(il, inst,
        lambda src : il.sign_extend(4, il.reg(2, src[0])),
        [inst.operands[0].register, inst.operands[1].register])

def lift_bn_mul(il, inst):
    return arith(il, inst,
        lambda src : il.mult(4, op_as_il(il, src[0]), op_as_il(il, src[1])),
        [inst.operands[0].register, inst.operands[1].register, inst.operands[2].register])

def lift_bn_div(il, inst):
    return arith(il, inst,
        lambda src : il.div_signed(4, op_as_il(il, src[0]), op_as_il(il, src[1])),
        [inst.operands[0].register, inst.operands[1].register, inst.operands[2].register])

def lift_bn_divu(il, inst):
    return arith(il, inst,
        lambda src : il.div_unsigned(4, op_as_il(il, src[0]), op_as_il(il, src[1])),
        [inst.operands[0].register, inst.operands[1].register, inst.operands[2].register])

def lift_bn_mod(il, inst):
    return arith(il, inst,
        lambda src : il.mod_signed(4, op_as_il(il, src[0]), op_as_il(il, src[1])),
        [inst.operands[0].register, inst.operands[1].register, inst.operands[2].register])

def lift_bn_modu(il, inst):
    return arith(il, inst,
        lambda src : il.mod_unsigned(4, op_as_il(il, src[0]), op_as_il(il, src[1])),
        [inst.operands[0].register, inst.operands[1].register, inst.operands[2].register])

def lift_bn_sll(il, inst):
    return arith(il, inst,
        lambda src : il.shift_left(4, op_as_il(il, src[0]), op_as_il(il, src[1])),
        [inst.operands[0].register, inst.operands[1].register, inst.operands[2].register])

def lift_bn_srl(il, inst):
    return arith(il, inst,
        lambda src : il.logical_shift_right(4, op_as_il(il, src[0]), op_as_il(il, src[1])),
        [inst.operands[0].register, inst.operands[1].register, inst.operands[2].register])

def lift_bn_sra(il, inst):
    return arith(il, inst,
        lambda src : il.arith_shift_right(4, op_as_il(il, src[0]), op_as_il(il, src[1])),
        [inst.operands[0].register, inst.operands[1].register, inst.operands[2].register])

def lift_bn_ror(il, inst):
    return arith(il, inst,
        lambda src : il.rotate_right(4, op_as_il(il, src[0]), op_as_il(il, src[1])),
        [inst.operands[0].register, inst.operands[1].register, inst.operands[2].register])

def lift_bn_slli(il, inst):
    return arith(il, inst,
        lambda src : il.shift_left(4, op_as_il(il, src[0]), op_as_il(il, src[1])),
        [inst.operands[0].register, inst.operands[1].register, inst.operands[2].immediate])

def lift_bn_srli(il, inst):
    return arith(il, inst,
        lambda src : il.logical_shift_right(4, op_as_il(il, src[0]), op_as_il(il, src[1])),
        [inst.operands[0].register, inst.operands[1].register, inst.operands[2].immediate])

def lift_bn_srai(il, inst):
    return arith(il, inst,
        lambda src : il.arith_shift_right(4, op_as_il(il, src[0]), op_as_il(il, src[1])),
        [inst.operands[0].register, inst.operands[1].register, inst.operands[2].immediate])

def lift_bn_rori(il, inst):
    return arith(il, inst,
        lambda src : il.rotate_right(4, op_as_il(il, src[0]), op_as_il(il, src[1])),
        [inst.operands[0].register, inst.operands[1].register, inst.operands[2].immediate])

def lift_bn_muli(il, inst):
    return arith(il, inst,
        lambda src : il.mult(4, op_as_il(il, src[0]), op_as_il(il, src[1])),
        [inst.operands[0].register, inst.operands[1].register, inst.operands[2].immediate])

def lift_bn_divi(il, inst):
    return arith(il, inst,
        lambda src : il.div_signed(4, op_as_il(il, src[0]), op_as_il(il, src[1])),
        [inst.operands[0].register, inst.operands[1].register, inst.operands[2].immediate])

def lift_bn_divui(il, inst):
    return arith(il, inst,
        lambda src : il.div_unsigned(4, op_as_il(il, src[0]), op_as_il(il, src[1])),
        [inst.operands[0].register, inst.operands[1].register, inst.operands[2].immediate])

def lift_bn_xori(il, inst):
    return arith(il, inst,
        lambda src : il.xor_expr(4, op_as_il(il, src[0]), op_as_il(il, src[1])),
        [inst.operands[0].register, inst.operands[1].register, inst.operands[2].immediate])


#
# Conditional Instructions
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
    return cond(il, inst,
        lambda src : il.compare_unsigned_greater_equal(4, op_as_il(il, src[0]), op_as_il(il, src[1])),
        [inst.operands[0].register, inst.operands[1].register])

def lift_bn_sfgts(il, inst):
    return cond(il, inst,
        lambda src : il.compare_signed_greater_than(4, op_as_il(il, src[0]), op_as_il(il, src[1])),
        [inst.operands[0].register, inst.operands[1].register])

def lift_bn_sfgtu(il, inst):
    return cond(il, inst,
        lambda src : il.compare_unsigned_greater_than(4, op_as_il(il, src[0]), op_as_il(il, src[1])),
        [inst.operands[0].register, inst.operands[1].register])

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

def lift_bn_cmov(il, inst):
    t = LowLevelILLabel()
    f = LowLevelILLabel()
    il.append(
        il.if_expr(
            il.compare_equal(
                4,
                op_as_il(il, inst.operands[0].register),
                op_as_il(il, inst.operands[1].register)
            ),
            t,
            f
        )
    )
    il.mark_label(t)
    il.append(
        il.set_reg(
            4,
            op_as_il(il, inst.operands[0].register),
            op_as_il(il, inst.operands[2].register)
        )
    )
    il.mark_label(f)
    return None


#
# Control Flow Instructions
#

def cond_jump(il, inst, expr, addr_op):
    mark_t = False
    mark_f = False

    jump_target = il.add(
        4, 
        il.const(4, il.current_address),
        il.sign_extend(4, il.const(4, addr_op))
    )

    t = il.get_label_for_address(Architecture["beyond2"], il.current_address + addr_op)
    if t is None:
        t = LowLevelILLabel()
        mark_t = True

    f = il.get_label_for_address(Architecture["beyond2"], il.current_address + inst.size)
    if f is None:
        f = LowLevelILLabel()
        mark_f = True

    il.append(
        il.if_expr(
            expr, 
            t,
            f
        )
    )

    if mark_t:
        il.mark_label(t)
    
    il.append(
        il.jump(
            jump_target
        )
    )

    if mark_f:
        il.mark_label(f)

# Flag-based instructions

def lift_bn_bf(il, inst):
    cond_jump(il, inst, il.flag("F"), inst.operands[0].non_pc_rel_immediate)
    return None

def lift_bn_bnf(il, inst):
    cond_jump(il, inst, il.not_expr(4, il.flag("F")), inst.operands[0].non_pc_rel_immediate)
    return None

def lift_bn_bo(il, inst):
    cond_jump(il, inst, il.flag("OV"), inst.operands[0].non_pc_rel_immediate)
    return None

def lift_bn_bno(il, inst):
    cond_jump(il, inst, il.not_expr(4, il.flag("OV")), inst.operands[0].non_pc_rel_immediate)
    return None

def lift_bn_bc(il, inst):
    cond_jump(il, inst, il.flag("C"), inst.operands[0].non_pc_rel_immediate)
    return None

def lift_bn_bnc(il, inst):
    cond_jump(il, inst, il.not_expr(4, il.flag("C")), inst.operands[0].non_pc_rel_immediate)
    return None

# Comparison-based instruction

def lift_bn_beqi(il, inst):
    cond_jump(il, inst, 
        il.compare_equal(
            4,
            op_as_il(il, inst.operands[0].register),
            op_as_il(il, inst.operands[1].immediate)
        ),
        inst.operands[2].non_pc_rel_immediate
    )

def lift_bn_bnei(il, inst):
    cond_jump(il, inst, 
        il.compare_not_equal(
            4,
            op_as_il(il, inst.operands[0].register),
            op_as_il(il, inst.operands[1].immediate)
        ),
        inst.operands[2].non_pc_rel_immediate
    )

def lift_bn_bgesi(il, inst):
    cond_jump(il, inst, 
        il.compare_signed_greater_equal(
            4,
            op_as_il(il, inst.operands[0].register),
            op_as_il(il, inst.operands[1].immediate)
        ),
        inst.operands[2].non_pc_rel_immediate
    )

def lift_bn_bgtsi(il, inst):
    cond_jump(il, inst, 
        il.compare_signed_greater_than(
            4,
            op_as_il(il, inst.operands[0].register),
            op_as_il(il, inst.operands[1].immediate)
        ),
        inst.operands[2].non_pc_rel_immediate
    )

def lift_bn_blesi(il, inst):
    cond_jump(il, inst, 
        il.compare_signed_less_equal(
            4,
            op_as_il(il, inst.operands[0].register),
            op_as_il(il, inst.operands[1].immediate)
        ),
        inst.operands[2].non_pc_rel_immediate
    )

def lift_bn_bltsi(il, inst):
    cond_jump(il, inst, 
        il.compare_signed_less_than(
            4,
            op_as_il(il, inst.operands[0].register),
            op_as_il(il, inst.operands[1].immediate)
        ),
        inst.operands[2].non_pc_rel_immediate
    )

def lift_bw_beq(il, inst):
    cond_jump(il, inst, 
        il.compare_equal(
            4,
            op_as_il(il, inst.operands[0].register),
            op_as_il(il, inst.operands[1].register)
        ),
        inst.operands[2].non_pc_rel_immediate
    )

def lift_bw_bne(il, inst):
    cond_jump(il, inst, 
        il.compare_not_equal(
            4,
            op_as_il(il, inst.operands[0].register),
            op_as_il(il, inst.operands[1].register)
        ),
        inst.operands[2].non_pc_rel_immediate
    )

def lift_bw_bges(il, inst):
    cond_jump(il, inst, 
        il.compare_signed_greater_equal(
            4,
            op_as_il(il, inst.operands[0].register),
            op_as_il(il, inst.operands[1].register)
        ),
        inst.operands[2].non_pc_rel_immediate
    )

def lift_bw_bgts(il, inst):
    cond_jump(il, inst, 
        il.compare_signed_greater_than(
            4,
            op_as_il(il, inst.operands[0].register),
            op_as_il(il, inst.operands[1].register)
        ),
        inst.operands[2].non_pc_rel_immediate
    )

# Unconditional jumps

def lift_return(il, inst):
    return il.ret(il.pop(4))

def lift_bn_j(il, inst):
    expr = None
    j_label = il.get_label_for_address(Architecture["beyond2"], il.current_address + inst.operands[0].non_pc_rel_immediate)
    
    if j_label is not None:
        expr = il.goto(j_label)
    else:
        expr = il.jump(il.current_address + inst.operands[0].non_pc_rel_immediate)

    return expr
    
def lift_bn_jr(il, inst):
    expr = None

    if disasm.is_return_inst(inst):
        expr = lift_return(il, inst)
    else:
        expr = il.jump(op_as_il(il, inst.operands[0].register))

    return expr

def lift_bl_jal(il, inst):
    return il.call(il.current_address + inst.operands[0].non_pc_rel_immediate)

def lift_bl_jalr(il, inst):
    return il.call(op_as_il(il, inst.operands[0].register))

#
# Memory Load/Store Instructions
#

def store(il, size, src_dst):
    return il.store(
        size,
        mem_operand(il, src_dst[0]),
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

#
# Stack Instructions
#

# nb.entri/bn.reti push n registers, beginning at r9.
def pushed_poped_registers(il, n, push):
    r = []
    for i in range(9, 9+n):
        if push:
            r.append(il.push(4, op_as_il(il, disasm.Register(i))))
        else:
            r.append(il.pop(4))
    return r

def lift_bn_entri(il, inst):
    pushed_regs = pushed_poped_registers(il, inst.operands[0].immediate, True)

    for reg in pushed_regs:
        il.append(reg)
    
    il.append(il.push(4 * inst.operands[1].immediate, il.const(4, 0)))

    return None

def lift_bn_reti(il, inst):
    pushed_regs = pushed_poped_registers(il, inst.operands[0].immediate, False)

    il.append(il.pop(4 * inst.operands[1].immediate))

    for reg in pushed_regs:
        il.append(reg)

    return None