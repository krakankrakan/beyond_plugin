# Get the position of the first left occuring 1
def get_first_one_pos(mask):
    pos = 0

    for i in range(0, 64):
        if mask & (1 << i) == (1 << i):
            pos = i
            break

    return pos

def get_last_one_pos(mask):
    pos = 0

    for i in range(0, 64):
        if mask & (1 << i) == (1 << i):
            pos = i

    return pos

def reverse_bits(n, width):
    result = 0
    for i in range(width):
        result <<= 1
        result |= n & 1
        n >>= 1
    return result

def get_signed_num(n, width):
    mask = (2 ** width) - 1
    if n & (1 << (width - 1)):
        return n | ~mask
    else:
        return n & mask