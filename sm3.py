import subprocess
import sys
import struct

# 循环左移函数（32位，与正确代码一致）
def circular_shift(value, bits):
    value &= 0xFFFFFFFF  # 32位截断
    return ((value << bits) | (value >> (32 - bits))) & 0xFFFFFFFF

# SM3置换函数P0（与正确代码一致）
def permutation_p0(value):
    p0_value = value ^ circular_shift(value, 9) ^ circular_shift(value, 17)
    return p0_value & 0xFFFFFFFF

# SM3置换函数P1（与正确代码一致）
def permutation_p1(value):
    p1_value = value ^ circular_shift(value, 15) ^ circular_shift(value, 23)
    return p1_value & 0xFFFFFFFF

# 获取Tj常量（核心修正：T0-T15=0x79cc4519，T16-T63=0x7a879d8a）
def get_T(j):
    if 0 <= j <= 15:
        return 0x79cc4519
    else:
        return 0x7a879d8a

# 布尔函数FFj（核心修正：0-15是XOR，16-63是与或）
def bool_func_ff(X, Y, Z, j):
    X, Y, Z = X & 0xFFFFFFFF, Y & 0xFFFFFFFF, Z & 0xFFFFFFFF
    if 0 <= j <= 15:
        return X ^ Y ^ Z
    else:
        return (X & Y) | (X & Z) | (Y & Z)

# 布尔函数GGj（核心修正：0-15是XOR，16-63是与或非）
def bool_func_gg(X, Y, Z, j):
    X, Y, Z = X & 0xFFFFFFFF, Y & 0xFFFFFFFF, Z & 0xFFFFFFFF
    if 0 <= j <= 15:
        return X ^ Y ^ Z
    else:
        return (X & Y) | ((~X) & 0xFFFFFFFF) & Z

# 消息填充函数（与正确代码一致，使用struct处理64位长度）
def prepare_data(data):
    L = len(data) * 8  # 原始消息长度（bit）
    padded_data = bytearray(data)
    padded_data.append(0x80)  # 附加0x80
    # 填充0x00直到长度模512等于448
    while (len(padded_data) * 8) % 512 != 448:
        padded_data.append(0x00)
    # 附加64位长度（大端序）
    padded_data.extend(struct.pack('>Q', L))
    return padded_data

# 消息扩展函数（与正确代码一致）
def expand_data_block(block):
    # 解析16个32位字（大端序）
    words = list(struct.unpack('>16I', block))
    # 生成W16-W67
    for j in range(16, 68):
        term1 = words[j-16] ^ words[j-9]
        term2 = circular_shift(words[j-3], 15)
        w_val = permutation_p1(term1 ^ term2) ^ circular_shift(words[j-13], 7) ^ words[j-6]
        words.append(w_val & 0xFFFFFFFF)
    # 生成W'0-W'63
    derived_words = []
    for j in range(64):
        derived_words.append((words[j] ^ words[j+4]) & 0xFFFFFFFF)
    return words, derived_words

# 压缩函数（核心修正：SS1计算、寄存器更新、异或输出）
def compression_step(Vi, Bi):
    words, derived_words = expand_data_block(Bi)
    A, B, C, D, E, F, G, H = Vi  # 初始化寄存器

    for j in range(64):
        Tj = get_T(j)
        # 计算SS1（与正确代码一致：Tj <<< (j mod 32)）
        tj_shifted = circular_shift(Tj, j % 32)
        ss1_term1 = circular_shift(A, 12)
        ss1 = (ss1_term1 + E + tj_shifted) & 0xFFFFFFFF
        ss1 = circular_shift(ss1, 7)
        # 计算SS2
        ss2 = (ss1 ^ ss1_term1) & 0xFFFFFFFF
        # 计算TT1和TT2
        tt1 = (bool_func_ff(A, B, C, j) + D + ss2 + derived_words[j]) & 0xFFFFFFFF
        tt2 = (bool_func_gg(E, F, G, j) + H + ss1 + words[j]) & 0xFFFFFFFF
        # 寄存器更新
        D_new = C
        C_new = circular_shift(B, 9)
        B_new = A
        A_new = tt1
        H_new = G
        G_new = circular_shift(F, 19)
        F_new = E
        E_new = permutation_p0(tt2)
        # 赋值新寄存器
        A, B, C, D = A_new, B_new, C_new, D_new
        E, F, G, H = E_new, F_new, G_new, H_new

    # 核心修正：最终输出是异或（而非加法）
    V_next = []
    V_current = [A, B, C, D, E, F, G, H]
    for i in range(8):
        V_next.append((Vi[i] ^ V_current[i]) & 0xFFFFFFFF)
    return V_next

def sm3_hash(message):
    """最终修正的SM3哈希函数（完全对齐正确代码）"""
    # 初始向量（与正确代码一致）
    initial_vector = [
        0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
        0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
    ]
    Vi = list(initial_vector)
    # 消息填充
    padded_data = prepare_data(message)
    # 分块压缩
    block_size = 64
    for i in range(0, len(padded_data), block_size):
        Bi = padded_data[i:i+block_size]
        Vi = compression_step(Vi, Bi)
    # 拼接哈希结果（大端序十六进制）
    return "".join([hex(x)[2:].zfill(8) for x in Vi])

def get_openssl_sm3(message):
    """调用OpenSSL计算SM3（兼容Windows/Linux）"""
    try:
        result = subprocess.run(
            ['openssl', 'dgst', '-sm3', '-hex'],
            input=message,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
            text=False
        )
        output = result.stdout.decode('utf-8').strip()
        return output.split()[-1].lower()
    except subprocess.CalledProcessError as e:
        print(f"❌ OpenSSL执行错误: {e.stderr.decode('utf-8')}")
        sys.exit(1)
    except FileNotFoundError:
        print(f"❌ 未找到OpenSSL，请安装OpenSSL 3.0+并添加到系统PATH")
        print("Windows下载地址: https://slproweb.com/products/Win32OpenSSL.html")
        sys.exit(1)

if __name__ == "__main__":
    # 测试用例（仅保留消息，移除标准预期值）
    test_cases = [
        ("abc".encode('utf-8'), "abc"),
        (b"", "空字符串"),
        ("12345678901234567890123456789012345678901234567890123456789012345678901234567890".encode('utf-8'), "1234567890重复字符串")
    ]

    print("=" * 80)
    print("SM3哈希实现验证（仅对比Python SM3与OpenSSL SM3）")
    print("=" * 80)

    all_pass = True
    for msg, msg_name in test_cases:
        python_sm3 = sm3_hash(msg)
        openssl_sm3 = get_openssl_sm3(msg)

        # 验证结果（仅对比Python和OpenSSL的结果）
        is_match = python_sm3 == openssl_sm3
        status = "✅ 结果一致" if is_match else "❌ 结果不一致"
        all_pass &= is_matchgi

        print(f"\n测试消息: {msg_name}")
        print(f"Python SM3:   {python_sm3}")
        print(f"OpenSSL SM3:  {openssl_sm3}")
        print(f"验证结果: {status}")

    print("\n" + "=" * 80)
    if all_pass:
        print("🎉 所有测试用例通过！Python SM3实现与OpenSSL完全一致！")
    else:
        print("⚠️ 部分测试用例失败，请检查OpenSSL版本是否为3.0+或代码实现！")
    print("=" * 80)

    sys.exit(0 if all_pass else 1)