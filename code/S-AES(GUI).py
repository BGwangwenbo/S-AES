import itertools
import time
import tkinter as tk
from tkinter import messagebox
from PIL import Image, ImageTk
import eencryption
import decryption


# 点击事件
# handle_cryption
def handle_cryption(param):
    plaintext = plaintext_entry.get()
    key = key_entry.get()
    ciphertext = ciphertext_entry.get()

    if (len(key) != 6 and len(key) != 10 and len(key) != 14) or not all(c in 'xX0123456789abcdefABCDEF' for c in key):
        messagebox.showerror("输入错误", "请输入有效的4位或8位或12位十六进制密钥")
        return
    key = int(key, 16)

    if param == 1:
        if len(plaintext)==6 and all(c in 'xX0123456789abcdefABCDEF' for c in plaintext):
            plaintext = int(plaintext,16)
            ciphertext = eencryption.encry(plaintext, key)
        else:
            ciphertext = eencryption.encry_string(plaintext, key)
        ciphertext_entry.delete(0,tk.END)
        ciphertext_entry.insert(0,ciphertext)
    elif param == 2:
        if len(ciphertext)==6 and all(c in 'xX0123456789abcdefABCDEF' for c in ciphertext):
            ciphertext = int(ciphertext,16)
            plaintext = decryption.decry(ciphertext, key)
        else:
            plaintext = decryption.decry_string(ciphertext, key)
        plaintext_entry.delete(0, tk.END)
        plaintext_entry.insert(0, plaintext)
    elif param == 3:
        ciphertext = eencryption.double_encry(plaintext, key)
        ciphertext_entry.delete(0, tk.END)
        ciphertext_entry.insert(0, ciphertext)
    elif param == 4:
        plaintext = decryption.double_decry(ciphertext, key)
        plaintext_entry.delete(0, tk.END)
        plaintext_entry.insert(0, plaintext)
    elif param == 5:
        ciphertext = eencryption.tertiary_encry(plaintext, key)
        ciphertext_entry.delete(0, tk.END)
        ciphertext_entry.insert(0, ciphertext)
    elif param == 6:
        plaintext = decryption.tertiary_decry(ciphertext, key)
        plaintext_entry.delete(0, tk.END)
        plaintext_entry.insert(0, plaintext)


# handle_cbc
def handle_cbc(param):
    plaintext = plaintext_entry.get()
    key = key_entry.get()
    vec = vector_entry.get()
    ciphertext = ciphertext_entry.get()

    if (len(key) != 6 and len(key) != 10 and len(key) != 14) or not all(c in 'xX0123456789abcdefABCDEF' for c in key):
        messagebox.showerror("输入错误", "请输入有效的4位或8位或12位十六进制密钥")
        return
    key = int(key, 16)
    vec = int(vec, 16)

    if param == 1:
        ciphertext=eencryption.CBC(plaintext,key,vec)
        ciphertext_entry.delete(0, tk.END)
        ciphertext_entry.insert(0, ciphertext)
    elif param == 2:
        plaintext = decryption.CBC_decry(ciphertext, key, vec)
        plaintext_entry.delete(0, tk.END)
        plaintext_entry.insert(0, plaintext)


# handle_mid_attack
def handle_mid_attack():
    plaintext = plaintext_entry.get()
    ciphertext = ciphertext_entry.get()
    key_list = eencryption.mid_attack(plaintext,ciphertext)
    if key_list == 0:
        key_entry.delete(0, tk.END)
        key_entry.insert(0, '无')
    else:
        key_entry.delete(0, tk.END)
        key_entry.insert(0, key_list)


# GUI部分

# 创建GUI窗口
window = tk.Tk()
window.title("字符串加密算法(建议十六进制输入或ASCII字符输入)")
window.geometry("630x480")

# 常用参数设置
win_w = 630
win_h = 480
margin = 30
padding_x = 20
padding_y = 20
# label和entry参数
lab_w = (win_w - margin * 2 - padding_x * 2) / 3
entry_w = 2 * (win_w - margin * 2 - padding_x * 2) / 3
lab_h = 40
entry_h = 40
# cmd参数
padding_cmd_x = 60
padding_cmd_y = 30
cmd_w = (win_w - margin * 4 - padding_cmd_x * 2) / 3
cmd_h = (win_h - margin * 2 - padding_y * 4 - padding_cmd_y * 2 - lab_h * 4) / 3

# 设置黑体字体
font_style = ("SimHei", 12, "bold")  # 字体名称和大小

# 加载背景图片
bg_image = Image.open("bg.jpg")  # 替换为你的图片路径
bg_image = bg_image.resize((630, 480), Image.LANCZOS)  # 调整图片大小
bg_photo = ImageTk.PhotoImage(bg_image)

# 创建一个 Label 来显示背景图片
bg_label = tk.Label(window, image=bg_photo)
bg_label.place(x=0, y=0, relwidth=1, relheight=1)  # 填满整个窗口

# #FAFAD2 鹅黄色
# r1
tk.Label(window, text="输入明文:", bg="#FAFAD2", font=font_style).place(x=margin, y=margin, width=lab_w, height=lab_h)
plaintext_entry = tk.Entry(window, bg="#FAFAD2")
plaintext_entry.place(x=margin + padding_x + lab_w, y=margin, width=entry_w, height=entry_h)
# r2
tk.Label(window, text="输入密钥:", bg="#FAFAD2", font=font_style).place(x=margin, y=margin + padding_y + lab_h,
                                                                        width=lab_w, height=lab_h)
key_entry = tk.Entry(window, bg="#FAFAD2")
key_entry.place(x=margin + padding_x + lab_w, y=margin + padding_y + lab_h, width=entry_w, height=entry_h)
# r3
tk.Label(window, text="输入IV:", bg="#FAFAD2", font=font_style).place(x=margin, y=margin + 2 * padding_y + 2 * lab_h,
                                                                        width=lab_w, height=lab_h)
vector_entry = tk.Entry(window, bg="#FAFAD2")
vector_entry.place(x=margin + padding_x + lab_w, y=margin + 2 * padding_y + 2 * lab_h, width=entry_w,
                       height=entry_h)
# r4
tk.Label(window, text="输入密文:", bg="#FAFAD2", font=font_style).place(x=margin, y=margin + 3 * padding_y + 3 * lab_h,
                                                                        width=lab_w, height=lab_h)
ciphertext_entry = tk.Entry(window, bg="#FAFAD2")
ciphertext_entry.place(x=margin + padding_x + lab_w, y=margin + 3 * padding_y + 3 * lab_h, width=entry_w,
                       height=entry_h)

# r5
encrypt_button = tk.Button(window, text="加密", bg="#FAFAD2", font=font_style, command=lambda: handle_cryption(1))
encrypt_button.place(x=margin * 2, y=margin + 4 * padding_y + 4 * lab_h, width=cmd_w, height=cmd_h)
decrypt_button = tk.Button(window, text="解密", bg="#FAFAD2", font=font_style, command=lambda: handle_cryption(2))
decrypt_button.place(x=margin * 2 + padding_cmd_x + cmd_w, y=margin + 4 * padding_y + 4 * lab_h,
                     width=cmd_w, height=cmd_h)
mid_attack_button = tk.Button(window, text="中间相遇攻击", bg="#FAFAD2", font=font_style, command=lambda: handle_mid_attack())
mid_attack_button.place(x=margin * 2 + 2 * padding_cmd_x + 2 * cmd_w, y=margin + 4 * padding_y + 4 * lab_h,
                            width=cmd_w, height=cmd_h)
# r6
double_encrypt_button = tk.Button(window, text="二重加密", bg="#FAFAD2", font=font_style, command=lambda: handle_cryption(3))
double_encrypt_button.place(x=margin * 2, y=margin + 4 * padding_y + padding_cmd_y + 4 * lab_h + cmd_h, width=cmd_w,
                            height=cmd_h)
double_decrypt_button = tk.Button(window, text="二重解密", bg="#FAFAD2", font=font_style, command=lambda: handle_cryption(4))
double_decrypt_button.place(x=margin * 2 + padding_cmd_x + cmd_w,
                            y=margin + 4 * padding_y + padding_cmd_y + 4 * lab_h + cmd_h,
                            width=cmd_w, height=cmd_h)
CBC_encrypt_button = tk.Button(window, text="CBC加密", bg="#FAFAD2", font=font_style, command=lambda: handle_cbc(1))
CBC_encrypt_button.place(x=margin * 2 + 2 * padding_cmd_x + 2 * cmd_w,
                            y=margin + 4 * padding_y + padding_cmd_y + 4 * lab_h + cmd_h,
                            width=cmd_w, height=cmd_h)
# r7
triple_encrypt_button = tk.Button(window, text="三重加密", bg="#FAFAD2", font=font_style, command=lambda: handle_cryption(5))
triple_encrypt_button.place(x=margin * 2, y=margin + 4 * padding_y + 2 * padding_cmd_y + 4 * lab_h + 2 * cmd_h,
                            width=cmd_w, height=cmd_h)
triple_decrypt_button = tk.Button(window, text="三重解密", bg="#FAFAD2", font=font_style, command=lambda: handle_cryption(6))
triple_decrypt_button.place(x=margin * 2 + padding_cmd_x + cmd_w,
                            y=margin + 4 * padding_y + 2 * padding_cmd_y + 4 * lab_h + 2 * cmd_h,
                            width=cmd_w, height=cmd_h)
CBC_decrypt_button = tk.Button(window, text="CBC解密", bg="#FAFAD2", font=font_style, command=lambda: handle_cbc(2))
CBC_decrypt_button.place(x=margin * 2 + 2 * padding_cmd_x + 2 * cmd_w,
                              y=margin + 4 * padding_y + 2 * padding_cmd_y + 4 * lab_h + 2 * cmd_h,
                              width=cmd_w, height=cmd_h)

window.mainloop()
