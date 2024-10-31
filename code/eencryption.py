import itertools
import decryption


# 密钥加
def key_plus(plaintext_bits, key_bits):
    return hex(plaintext_bits ^ key_bits)


# 半字节替换
def half_byte_sub(hex_value):
    # 定义 S-Box
    S_box = [[9,4,'A','B'],['D',1,8,5],[6,2,0,3],['C','E','F',7]]
    
    binary_string = bin(hex_value)[2:].zfill(16)
    binary_string=str(binary_string)
    
    substituted_values = "0x"
    
    # 遍历每个半字节（4位）
    for i in range(0, len(binary_string), 4):

        half_byte = binary_string[i:i+4]
        index = int(half_byte, 2)  # 将半字节转换为十进制
        
        # 计算行和列
        row = index >> 2  # 取高2位作为行索引
        col = index & 0x03  # 取低2位作为列索引
        
        # 进行替换
        value = S_box[row][col]

        substituted_values+=str(value)

    return substituted_values


# 行位移
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


# 列混淆
def mix_columns(text):
    """ 对输入的 2x2 矩阵进行混淆 """

    binary_string = bin(text)[2:].zfill(16)
    matrix=[[],[]]
    matrix[0].append(int(binary_string[0:4],2))
    matrix[0].append(int(binary_string[8:12],2))
    matrix[1].append(int(binary_string[4:8],2))
    matrix[1].append(int(binary_string[12:16],2))

    # 乘法矩阵
    mix_matrix = [[1, 4], [4, 1]]
    
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

    w5=w4^w3

    return int(bin(w0)[2:].zfill(8)+bin(w1)[2:].zfill(8),2),int(bin(w2)[2:].zfill(8)+bin(w3)[2:].zfill(8),2),int(bin(w4)[2:].zfill(8)+bin(w5)[2:].zfill(8),2)


# 整体加密函数（一重加密）
def encry(plaintext,key): # 输入int 输出结果为16进制的字符串
    # 生成密钥
    w01,w23,w45 = key_expansion(key)

    # 第0轮：轮密钥加--------------------
    proce_text = int(key_plus(plaintext,w01),16)
    # 第一轮---------------------------
    # 半字节替换
    proce_text=int(half_byte_sub(proce_text),16)
    # 行位移
    proce_text=int(swap_nibbles(proce_text),16)
    # 列混淆
    proce_text=int(mix_columns(proce_text),16)
    # 轮密钥加
    proce_text = int(key_plus(proce_text,w23),16)
    # 第二轮------------------------------
    # 半字节替换
    proce_text=int(half_byte_sub(proce_text),16)
    # 行位移
    proce_text=int(swap_nibbles(proce_text),16)
    # 轮密钥加
    proce_text = int(key_plus(proce_text,w45),16)

    return '0x'+hex(proce_text)[2:].zfill(4)


# 字符串加密函数（第三关：输入字符串进行加密）
def encry_string(s,key):  # 输入字符串 输出字符串
    # 将字符串转换为十六进制字符串  
    hex_string = ''.join(hex(ord(char))[2:] for char in s)  # 使用格式化字符串

    # 计算需要的填充位数，将字符串长度填充到4的倍数
    segment=4
    total_length = len(hex_string)   
    padding_bits = (segment - (total_length % segment)) %segment
    # 在开头填充 0
    hex_string = '0' * padding_bits  + hex_string

    # 将16进制字符串划分为形如0xaabb的多个segment 
    segments = []
    for i in range(0, len(hex_string), 4):
        start_index = i
        segment = hex_string[i:i+4]
        segments.append(f'0x{segment}')  # 确保每段都有 4 个字符

    # 对每个segment进行加密，得到最终加密的密文
    encrypted_string = ""
    for i in segments:
        encry_segment = int(i,16)
        encrypted_string += encry(encry_segment,key)[2:].zfill(4)

    result = ''
    for i in range(0,len(encrypted_string),2):
        result+=chr(int(encrypted_string[i:i+2],16))
    return result


# 整体加密函数（第四关：双重加密，输入32bit密钥）
def double_encry(plaintext,key):
    
    # 将32bit密钥分为两把16bit密钥
    key_32 = hex(key)
    key1 = int(key_32[2:6],16)
    key2 = int(key_32[6:10],16)
    if type(plaintext)==int:
        temp = encry(plaintext, key1)
        temp_string = int(temp, 16)
        proce_text = encry(temp_string, key2)
        return proce_text
    else:
        temp = encry_string(plaintext, key1)
        proce_text = encry_string(temp, key2)
        return proce_text


# 整体加密函数（第四关：三重加密,输入48bit密钥）
def tertiary_encry(plaintext,key):
    
    # 将48bit密钥分为三把16bit密钥
    key_48 = hex(key)
    key1 = int(key_48[2:6],16)
    key2 = int(key_48[6:10],16)
    key3 = int(key_48[10:14],16)
    if type(plaintext)==int:
        temp = encry(plaintext, key1)
        temp_string = int(temp, 16)
        temp2 = encry(plaintext, key2)
        temp2_string = int(temp2, 16)
        proce_text = encry(temp2_string, key3)
        return proce_text
    else:
        temp = encry_string(plaintext, key1)
        temp2 = encry_string(plaintext, key2)
        proce_text = encry_string(temp2, key3)
        return proce_text


def CBC(plaintext, key, vector):
    # 将字符串转换为十六进制字符串
    hex_string = ''.join(hex(ord(char))[2:] for char in plaintext)  # 使用格式化字符串

    # 计算需要的填充位数，将字符串长度填充到4的倍数
    segment = 4
    total_length = len(hex_string)
    padding_bits = (segment - (total_length % segment)) % segment

    # 在开头填充 0
    hex_string = '0' * padding_bits + hex_string

    # 将16进制字符串划分为形如0xaabb的多个segment
    segments = []
    for i in range(0, len(hex_string), 4):
        segment = hex_string[i:i + 4]
        segments.append(f'0x{segment}')

    # CBC加密
    encrypted_string = ""
    for i in segments:
        encry_segment = int(i, 16)
        encrypted_segment = encry(encry_segment ^ vector, key)[2:].zfill(4)
        vector = int(encrypted_segment,16)
        encrypted_string += encrypted_segment

    result = ''
    for i in range(0, len(encrypted_string), 2):
        result += chr(int(encrypted_string[i:i + 2], 16))
    return result


# 中间相遇攻击（破解双重加密）
def generate_keys():
    print('0')
    return ['0x'+''.join(bits) for bits in itertools.product('0123456789ABCDEF', repeat=4)]


def mid_attack(plaintext, ciphertext):
    key_list=""
    judge1=False
    judge2=False
    dict1={}
    dict2={}
    if len(plaintext) == 6 and all(c in 'xX0123456789abcdef' for c in plaintext):
        judge1 = True
        plaintext=int(plaintext,16)
    if len(ciphertext) == 6 and all(c in 'xX0123456789abcdef' for c in ciphertext):
        judge2 = True
        ciphertext=int(ciphertext,16)

    for key1 in generate_keys():
        if judge1:
            temp_ciphertext = encry(plaintext, int(key1,16))
            dict1[temp_ciphertext]=key1  # 键值互换，使用中间值做键，密钥做值
        else:
            temp_ciphertext = encry_string(plaintext, int(key1,16))
            dict1[temp_ciphertext]=key1
    print('1')
    for key2 in generate_keys():
        if judge2:
            temp_plaintext = decryption.decry(ciphertext, int(key2,16))
            dict2[temp_plaintext] = key2
        else:
            temp_plaintext = decryption.decry_string(ciphertext, int(key2,16))
            dict2[temp_plaintext] = key2
    print('2')
    common_keys = dict1.keys() & dict2.keys()
    for keys in common_keys:
        if key_list == '':
            key_list += dict1[keys] + dict2[keys][2:]
        else:
            key_list += '或' + dict1[keys] + dict2[keys]
    print('3')
    if key_list != "":
        return key_list
    else:
        return 0


# 示例用法
def main():
    plaintext = int(input("请输入明文(16bit),例如0x2233："), 16)
    # 密钥
    key16 = 0x2233
    key32 = 0x43d723b5
    key48 = 0x2351aca27e91
    vec = 0x1234
    plaintext_string = input("请输入加密的字符串，例如“good morning”:")

    encrypted_text = encry(plaintext, key16)
    double_encrypted_text = double_encry(plaintext, key32)
    tertiary_encrypted_text = tertiary_encry(plaintext, key48)
    encrypted_string = encry_string(plaintext_string, key16)
    cbc_string = CBC(plaintext_string, key16, vec)
    key = mid_attack('asda','asdf')

    print(f"{hex(plaintext)}加密后的结果为：{encrypted_text}")

    print(f"{hex(plaintext)}二次加密后的结果为：{double_encrypted_text}")

    print(f"{hex(plaintext)}三次加密后的结果为：{tertiary_encrypted_text}")

    print(f"{plaintext_string}加密后的结果为：{encrypted_string}")

    print(f"{plaintext_string}加密后的结果为：{cbc_string}")
    print(f"{''}中间相遇攻击后的结果为：{key}")


if __name__ == "__main__":
    main()
