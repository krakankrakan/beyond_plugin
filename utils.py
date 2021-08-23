# Get the position of the first left occuring 1
def get_first_one_pos(mask):
    pos = 0

    for i in range(0, 64):
        if mask & (1 << i) == (1 << i):
            pos = i
            break

    return pos