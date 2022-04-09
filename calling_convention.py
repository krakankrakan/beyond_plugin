from binaryninja import CallingConvention

class BeyondCallingConvention(CallingConvention):
    name = "BeyondCall"
    caller_saved_regs = (
        "r11",
        "r9",
        "r8",
        "r7",
        "r6",
        "r5",
        "r4",
        "r3",
        "r2"
    )
    callee_saved_regs = (
        "r31",
        "r29",
        "r27",
        "r25",
        "r23",
        "r21",
        "r19",
        "r17",
        "r15",
        "r13",
        "r10",
    )
    int_arg_regs = ("r3", "r4", "r5", "r6", "r7", "r8")
    int_return_reg = "r11"