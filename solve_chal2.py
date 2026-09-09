#!/usr/bin/env python3
"""To verify the valid key."""

import zipfile

MASK32 = 0xFFFFFFFF
P = 0x01000193
P_INV = 0x359C449B
TARGET = 0x86D03165
RECOVERED_KEY_HEX = "49415443517b414141414141414141414e20083041417d4e9141a74125da107d"
ALLOWED = bytes(range(48, 58)) + bytes(range(65, 91)) + b"_" + bytes(range(97, 123))
ALLOWED_SET = set(ALLOWED)


def decrypt():
    with zipfile.ZipFile("Custom+VM.zip") as archive:
        elf = archive.read("Custom VM/hyperstate/hyperstate4")
    state, output = 0xC0FFEE42, []
    for byte in elf[0x20C0:0x221D]:
        state = (state * 0x41C64E6D + 0x3039) & MASK32
        output.append(byte ^ ((state >> 16) & 0xFF))
    return output[:256], output[256:]


SBOX, CODE = decrypt()
INV = [0] * 256
for i, value in enumerate(SBOX):
    INV[value] = i


def rol3(value):
    return ((value << 3) | (value >> 5)) & 0xFF


def required_current(index, state, following, stride):
    """Invert both S-box rounds to recover input[index]."""
    return INV[stride ^ following] ^ state ^ index ^ SBOX[following ^ rol3(state)]


def hash_forward(checksum, index, following, stride):
    checksum = ((checksum ^ following) * P) & MASK32
    return ((checksum ^ ((stride << 8) | index)) * P) & MASK32


def hash_reverse(checksum, index, following, stride):
    checksum = ((checksum * P_INV) & MASK32) ^ ((stride << 8) | index)
    return (((checksum * P_INV) & MASK32) ^ following) & MASK32


def vm_round(index, state, checksum, candidate):
    current = candidate[index] if index <= 31 else 0
    next_index = (index + 1) & 0xFF
    following = candidate[next_index] if next_index <= 31 else 0
    first = SBOX[following ^ rol3(state)] ^ current
    stride = SBOX[first ^ state ^ index] ^ following
    return (
        (index + stride) & 0xFF,
        following ^ stride,
        hash_forward(checksum, index, following, stride),
    )


def solve():
    partial = bytearray(32)
    partial[:6] = b"IATCQ{"
    index, state, checksum = 0, 0x42, 0x811C9DC5
    for _ in range(7):
        index, state, checksum = vm_round(index, state, checksum, partial)
    assert (index, state, checksum) == (5, 0x44, 0xCBBD2041)
    bridge = ord("M")
    assert required_current(5, state, bridge, 2) == ord("{")
    checksum = hash_forward(checksum, 5, bridge, 2)
    indices = (7, 9, 11, 13, 15, 17, 19, 21)
    strides = (2, 2, 2, 2, 2, 2, 2, 11)

    forward = {}

    def first_half(step, value, previous, pairs):
        if step == 4:
            forward[(value, previous)] = tuple(pairs)
            return
        vm_state = previous ^ (2 if step == 0 else strides[step - 1])
        for following in ALLOWED:
            current = required_current(indices[step], vm_state, following, strides[step])
            if current not in ALLOWED_SET:
                continue
            pairs.append((current, following))
            first_half(step + 1, hash_forward(value, indices[step], following, strides[step]), following, pairs)
            pairs.pop()

    first_half(0, checksum, bridge, [])
    answer = None

    def second_half(step, value_after, next_following, reverse_pairs):
        nonlocal answer
        if answer is not None:
            return
        if step < 4:
            for previous in ALLOWED:
                current = required_current(indices[4], previous ^ strides[3], next_following, strides[4])
                if current in ALLOWED_SET and (value_after, previous) in forward:
                    answer = (forward[(value_after, previous)], tuple(reversed(reverse_pairs)))
                    return
            return
        for following in ALLOWED:
            value_before = hash_reverse(value_after, indices[step], following, strides[step])
            if next_following is not None:
                current = required_current(indices[step + 1], following ^ strides[step], next_following, strides[step + 1])
                if current not in ALLOWED_SET:
                    continue
            reverse_pairs.append((None, following))
            second_half(step - 1, value_before, following, reverse_pairs)
            reverse_pairs.pop()
            if answer is not None:
                return

    second_half(7, TARGET, None, [])
    assert answer is not None

    pairs = [list(pair) for pair in answer[0] + answer[1]]
    previous, previous_stride = bridge, 2
    for step in range(8):
        pairs[step][0] = required_current(indices[step], previous ^ previous_stride, pairs[step][1], strides[step])
        previous, previous_stride = pairs[step][1], strides[step]

    candidate = bytearray(b"A" * 32)
    candidate[:7] = b"IATCQ{M"
    candidate[31] = ord("}")
    for index, pair in zip(indices, pairs):
        candidate[index:index + 2] = bytes(pair)
    return bytes(candidate)


def interpret(candidate):
    if len(candidate) != 32:
        return False, None, 0
    registers = [0] * 16
    checksum, zero, result, pc, rounds = 0x811C9DC5, False, False, 0, 0
    while pc <= 0x5C:
        opcode, left, right = CODE[pc:pc + 3]
        next_pc = pc + 3
        if opcode == 0xB2:
            registers[left] = right
        elif opcode == 0xA1:
            source = registers[right]
            registers[left] = candidate[source] if source <= 31 else 0
        elif opcode == 0xA7:
            registers[left] = registers[right]
        elif opcode == 0xD4:
            registers[left] = (registers[left] + registers[right]) & 0xFF
        elif opcode == 0xE5:
            registers[left] = rol3(registers[left])
        elif opcode == 0xB6:
            registers[left] = SBOX[registers[left]]
        elif opcode == 0xC3:
            zero = registers[left] == registers[right]
            registers[left] ^= registers[right]
        elif opcode == 0xF6:
            checksum = hash_forward(checksum, registers[1], registers[left], registers[right])
            rounds += 1
        elif opcode == 0x17:
            if not zero:
                next_pc = left
        elif opcode == 0xE9:
            result = registers[1] == 32 and checksum == TARGET
        else:
            # The byte is deliberately invalid.
            return result, checksum, rounds
        pc = next_pc
    return result, checksum, rounds


if __name__ == "__main__":
    # This key is recovered by path_mitm.c.  It contains non-printable bytes, therefore we retain and pass it as hexadecimal rather than as text.
    key = bytes.fromhex(RECOVERED_KEY_HEX)
    accepted, checksum, rounds = interpret(key)
    print(f"key (hex): {key.hex()}")
    print(f"length: {len(key)}")
    print(f"rounds: {rounds}")
    print(f"checksum: 0x{checksum:08x}")
    print(f"VM result: {'ACCESS GRANTED' if accepted else 'ACCESS DENIED'}")
    if not accepted:
        raise SystemExit(1)
