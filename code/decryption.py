# 密钥加（不变，同加密）
def key_plus(plaintext_bits, key_bits):
    return hex(plaintext_bits ^ key_bits)


# 半字节替换
def half_byte_sub(hex_value):
    # 定义 S-Box
    S_box = [[9,4,'A','B'],['D',1,8,5],[6,2,0,3],['C','E','F',7]]
    
    binary_string = bin(hex_value)[2:].zfill(16)
    binary_string=str(binary_string)
    substituted_values = ""
    
    # 遍历每个半字节（4位）
    for i in range(0, len(binary_string), 4):

        half_byte = binary_string[i:i+4]
        index = int(half_byte, 2)  # 将半字节转换为十进制
        
        # 计算行和列
        row = index >> 2  # 取高2位作为行索引
        col = index & 0x03  # 取低2位作为列索引
        
        # 进行替换
        substituted_value = S_box[row][col]
        substituted_values= substituted_values+str(substituted_value)

    return hex(int(substituted_values,16))


# 逆半字节替换
def de_half_byte_sub(hex_value):
    # 定义 S-Box
    S_box = [['A',5,9,'B'],[1,7,8,'F'],[6,0,2,3],['C',4,'D','E']]
    
    binary_string = bin(hex_value)[2:].zfill(16)
    binary_string=str(binary_string)
    substituted_values = ""
    
    # 遍历每个半字节（4位）
    for i in range(0, len(binary_string), 4):

        half_byte = binary_string[i:i+4]
        index = int(half_byte, 2)  # 将半字节转换为十进制
        
        # 计算行和列
        row = index >> 2  # 取高2位作为行索引
        col = index & 0x03  # 取低2位作为列索引
        
        # 进行替换
        substituted_value = S_box[row][col]
        substituted_values= substituted_values+str(substituted_value)

    return hex(int(substituted_values,16))


# 行位移（不变，同加密）
def swap_nibbles(hex_value):
    # 将十六进制数转换为二进制字符串
    binary_string = bin(hex_value)[2:].zfill(16) # 填充到16位

    nibble1 = binary_string[0:4]    # 第1个半字节
    nibble2 = binary_string[4:8]     # 第2个半字节
    nibble3 = binary_string[8:12]    # 第3个半字节
    nibble4 = binary_string[12:16]   # 第4个半字节

    # 进行交换
    new_binary_string = nibble1 + nibble4 + nibble3 + nibble2

    # 将新的二进制字符串转换回十六进制

    return hex(int(new_binary_string, 2))


# 列混淆中的加函数
def add_gf2_4(a, b):
    """ 在 GF(2^4) 中进行加法（异或） """
    return a ^ b
# 列混淆中的乘函数
def multiply_gf2_4(a, b):
    """ 在 GF(2^4) 中进行乘法 """
    result = 0
    while b > 0:
        if b & 1:  # 如果 b 的最低位为 1
            result ^= a  # 将 a 加到结果中（异或）
        a <<= 1  # 将 a 左移一位
        # 如果 a 左移后大于 0xF（15），则减去不可约多项式 0b10011
        if a > 0xF:
            a ^= 0b10011
        b >>= 1  # 将 b 右移一位
    return result


# 逆列混淆
def de_mix_columns(text):
    """ 对输入的 2x2 矩阵进行混淆 """

    binary_string = bin(text)[2:].zfill(16)
    matrix=[[],[]]
    matrix[0].append(int(binary_string[0:4],2))
    matrix[0].append(int(binary_string[8:12],2))
    matrix[1].append(int(binary_string[4:8],2))
    matrix[1].append(int(binary_string[12:16],2))

    # 乘法矩阵
    mix_matrix = [[9, 2], [2, 9]]
    
    # 结果矩阵
    mixed_matrix = [[0, 0], [0, 0]]
    
    # 执行矩阵乘法
    for i in range(2):
        for j in range(2):
            mixed_value = 0
            mixed_value = add_gf2_4(multiply_gf2_4(mix_matrix[i][0], matrix[0][j]),multiply_gf2_4(mix_matrix[i][1],matrix[1][j]))

            mixed_matrix[i][j] = mixed_value

    result = '0x'

    for i in range(2):
        for j in range(2):
            result+= hex(mixed_matrix[j][i])[2:]
    
    return result


# 密钥扩展
def key_expansion(key):
    """ 密钥扩展函数，将128位密钥扩展为多个轮密钥 """
    # 密钥长度

    binary_string = bin(key)[2:].zfill(16)
    w0=int(binary_string[0:8],2)
    w1=int(binary_string[8:16],2)

    front_half_w1= bin(w1)[2:].zfill(8)[0:4]
    latter_half_w1=bin(w1)[2:].zfill(8)[4:]
    rotnib_w1=int(latter_half_w1+front_half_w1,2)
    w2=w0^128^int(half_byte_sub(rotnib_w1)[4:],16)

    w3=w2^w1
    front_half_w3= bin(w3)[2:].zfill(8)[0:4]
    latter_half_w3=bin(w3)[2:].zfill(8)[4:]
    rotnib_w3=int(latter_half_w3+front_half_w3,2)

    w4=w2^48^int(half_byte_sub(rotnib_w3)[4:],16)

    w5=w4 ^ w3

    return int(bin(w0)[2:].zfill(8)+bin(w1)[2:].zfill(8),2),int(bin(w2)[2:].zfill(8)+bin(w3)[2:].zfill(8),2),int(bin(w4)[2:].zfill(8)+bin(w5)[2:].zfill(8),2)


# 整体解密函数
def decry(plaintext,key):
    # 生成密钥
    w01,w23,w45 = key_expansion(key)

    # 第0轮：轮密钥加--------------------
    proce_text = int(key_plus(plaintext,w45),16)
    # 第一轮---------------------------
    # 逆行位移
    proce_text=int(swap_nibbles(proce_text),16)
    #逆半字节替换
    proce_text=int(de_half_byte_sub(proce_text),16)
    # 轮密钥加
    proce_text=int(key_plus(proce_text,w23),16)
    # 逆列混淆
    proce_text=int(de_mix_columns(proce_text),16)
    # 逆行位移
    proce_text=int(swap_nibbles(proce_text),16)
    # 逆半字节替换
    proce_text=int(de_half_byte_sub(proce_text),16)
    # 轮密钥加
    proce_text=int(key_plus(proce_text,w01),16)

    return '0x'+hex(proce_text)[2:].zfill(4)


# 字符串解密函数，对加密后的十六进制字符串解密输出结果（第三关）
def decry_string(s,key):
    text = ''.join(hex(ord(char))[2:] for char in s)  # 使用格式化字符串
    segment=4

    # 计算需要的填充位数
    total_length = len(text)   # 每个十六进制字符对应 4 位
    padding_bits = (segment - (total_length % segment)) %segment
    text = '0' * padding_bits + text

    # 划分为形如0xaabb的每个segment 
    segments = []
    for i in range(0, len(text), 4):
        segment = text[i:i+4]
        segments.append(f'0x{segment}')  # 确保每段都有 4 个字符
    
    # 对每个segment进行解密
    decrypted_string = ""

    for i in segments:
        decry_segment = int(i,16)
        decrypted_string += decry(decry_segment,key)[2:].zfill(4)

    # 转换为字符串

    # 将十六进制字符串转换为 ASCII 字符串
    text_string = ''
    # 将十六进制字符串每两个字符分组
    for i in range(0, len(decrypted_string), 2):
        # 获取每个字节的十六进制值
        byte = decrypted_string[i:i + 2]
        # 将十六进制转换为十进制整数，然后转换为字符
        text_string += chr(int(byte, 16))


    return text_string


# 整体二次解密函数（第四关：双重加密）
def double_decry(plaintext,key):
    key_32 = hex(key)
    key1 = int(key_32[2:6],16)
    key2 = int(key_32[6:10],16)
    if type(plaintext)==int:
        temp = decry(plaintext, key1)
        temp_string = int(temp, 16)
        proce_text = decry(temp_string, key2)
        return proce_text
    else:
        temp = decry_string(plaintext, key1)
        proce_text = decry_string(temp, key2)
        return proce_text


# 整体二次解密函数（第四关：双重加密）
def tertiary_decry(plaintext,key):
    key_48 = hex(key)
    key1 = int(key_48[2:6],16)
    key2 = int(key_48[6:10],16)
    key3 = int(key_48[10:14],16)
    if type(plaintext) == int:
        temp = decry(plaintext, key1)
        temp_string = int(temp, 16)
        temp2 = decry(plaintext, key2)
        temp2_string = int(temp2, 16)
        proce_text = decry(temp2_string, key3)
        return proce_text
    else:
        temp = decry_string(plaintext, key1)
        temp2 = decry_string(plaintext, key2)
        proce_text = decry_string(temp2, key3)
        return proce_text


def CBC_decry(ciphertext, key, vector):
    """ciphertext为str,其长度必为2的倍数"""

    # hex_string = ''.join(hex(ord(char))[2:] for char in ciphertext)
    ciphertext = ''.join(hex(ord(char))[2:] for char in ciphertext)

    # 划分为形如0xaabb的每个segment
    segments = []
    for i in range(0, len(ciphertext), 4):
        segment = ciphertext[i:i + 4]
        segments.append(f'0x{segment}')  # 确保每段都有 4 个字符

    # 对每个segment进行解密
    decrypted_segments = ""
    for i in segments:
        decry_segment = int(i, 16)
        decrypted_segment = int(decry(decry_segment, key)[2:], 16) ^ vector
        vector = decry_segment
        decrypted_segments += hex(decrypted_segment)[2:]

    # 转换为字符串

    # 将十六进制字符串转换为 ASCII 字符串
    text_string = ''

    # 将十六进制字符串每两个十六进制分组
    for i in range(0, len(decrypted_segments), 2):
        # 获取每个字节的十六进制值
        byte = decrypted_segments[i:i + 2]
        # 将十六进制转换为十进制整数，然后转换为字符
        text_string += chr(int(byte, 16))

    return text_string


# 示例用法
def main():
    ciphertext1 = int(input("请输入一次加密密文(16bit),例如0x2233："), 16)
    ciphertext2 = int(input("请输入二次加密密文(16bit),例如0x2233："), 16)
    ciphertext3 = int(input("请输入三次加密密文(16bit),例如0x2233："), 16)
    # 密钥
    key16 = 0x2233
    key32 = 0x43d723b5
    key48 = 0x2351aca27e91
    cipherstring = input("请输入加密后的字符串(16bit)，例如“0x12563abced”:")

    encrypted_text = decry(ciphertext1, key16)
    double_encrypted_text = double_decry(ciphertext2, key32)
    tertiary_encrypted_text = tertiary_decry(ciphertext3, key48)
    encrypted_string = decry_string(cipherstring, key16)

    print(f"{hex(ciphertext1)}解密后的结果为：{encrypted_text}")

    print(f"{hex(ciphertext2)}二次解密后的结果为：{double_encrypted_text}")

    print(f"{hex(ciphertext3)}三次解密后的结果为：{tertiary_encrypted_text}")

    print(f"{cipherstring}解密后的结果为：{encrypted_string}")


if __name__ == "__main__":
    main()
