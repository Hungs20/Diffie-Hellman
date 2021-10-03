import tkinter as tk
from tkinter import *
from tkinter import messagebox
from tkinter.font import BOLD

class DH_Endpoint(object):
    def __init__(self, g, p, private_key):
        self.g = g
        self.p = p
        self.private_key = private_key
        self.full_key = None
        
    def generate_shared_key(self):
        shared_key = self.g**self.private_key
        shared_key = shared_key%self.p
        return shared_key
    
    def generate_full_key(self, shared_key):
        full_key = shared_key**self.private_key
        full_key = full_key%self.p
        self.full_key = full_key
        return full_key
    
    def encrypt_message(self, message):
        encrypted_message = ""
        key = self.full_key
        for c in message:
            encrypted_message += chr(ord(c)+key)
        return encrypted_message
    
    def decrypt_message(self, encrypted_message):
        if self.full_key == None:
            return ""
        decrypted_message = ""
        key = self.full_key
        for c in encrypted_message:
            decrypted_message += chr(ord(c)-key)
        return decrypted_message
    
def create_ui():
    g = 197
    p = 151
    alice_private_key = 199
    bob_private_key = 157
    message = ""

    Alice = DH_Endpoint(g, p, alice_private_key)
    Bob = DH_Endpoint(g, p, bob_private_key)

    def get_shared_key_alice():
        private_key = private_alice_input.get()
        try:
            private_key = int(private_key)
        except ValueError:
            messagebox.showerror('Lỗi', 'Key phải là số nguyên')
            return
        Alice = DH_Endpoint(g, p, private_key)
        alice_shared_key = Alice.generate_shared_key()
        lbl_alice_shared_key_result.config(text=alice_shared_key)
        print("Alice share key: " , alice_shared_key)
        
        return
    def get_shared_key_bob():
        private_key = private_bob_input.get()
        try:
            private_key = int(private_key)
        except ValueError:
            messagebox.showerror('Lỗi', 'Key phải là số nguyên')
            return
        Bob = DH_Endpoint(g, p, private_key)
        bob_shared_key = Bob.generate_shared_key()
        lbl_bob_shared_key_result.config(text=bob_shared_key)
        print("Bob share key: " , bob_shared_key)
        return
    def decrypt_alice_message():
        text = cipher_alice_input.get()
        get_shared_key_bob()
        shared_key = Bob.generate_shared_key()
        full_key = Alice.generate_full_key(shared_key)
        print("Alice full key: " , full_key)
        result = Alice.decrypt_message(text)
        lbl_message_alice.config(text=result)
        return
    def decrypt_bob_message():
        text = cipher_bob_input.get()
        get_shared_key_alice()
        shared_key = Alice.generate_shared_key()
        full_key = Bob.generate_full_key(shared_key)
        print("Bob full key: " , full_key)
        result = Bob.decrypt_message(text)
        lbl_message_bob.config(text=result)
        return
    def send_alice_btn_press():
        plain_text = msg_input.get()
        get_shared_key_alice()
        shared_key = Alice.generate_shared_key()
        full_key = Bob.generate_full_key(shared_key)
        print("Bob full key: " , full_key)
        decrypt_text = Bob.encrypt_message(plain_text)
        cipher_alice_input.delete(0, END)
        cipher_alice_input.insert(0, decrypt_text)
        lbl_message_alice.config(text="")
        return
    
    def send_bob_btn_press():
        plain_text = msg_input.get()
        get_shared_key_bob()
        shared_key = Bob.generate_shared_key()
        full_key = Alice.generate_full_key(shared_key)
        print("Alice full key: " , full_key)
        decrypt_text = Alice.encrypt_message(plain_text)
        cipher_bob_input.delete(0, END)
        cipher_bob_input.insert(0, decrypt_text)
        lbl_message_bob.config(text="")
        return
    window = Tk()
    window.geometry('700x400')
    window.title("Diffie-Hellman")
    
    title = Label(window, text = "Diffie-Hellman", bg="orange", width=300, height=3)
    title.config(font =("Courier", 30))
    title.pack()

    row = Frame(window)
    lbg = "g = {}".format(g)
    lbl_g = Label(row, text=lbg, width = 10, font=("Courier", 18))
    lbp = "p = {}".format(p)
    lbl_p = Label(row, text=lbp, width = 10, font=("Courier", 18))

    row.pack(side = TOP, padx = 5 , pady = 5)
    lbl_g.pack(side = LEFT)
    lbl_p.pack(side = LEFT)

    row_index = Frame(window)
    row_index.pack()
    row_alice = Frame(row_index)
    row_bob = Frame(row_index)

    lbl_alice = Label(row_alice, text="Alice", fg="green", font=("Courier-Bold", 20))

    row_alice_private_key = Frame(row_alice)
    lbl_alice_private_key = Label(row_alice_private_key, text="Private key: ")
    private_alice_input = Entry(row_alice_private_key, width=5,fg="green", justify=CENTER)
    private_alice_input.insert(0, alice_private_key)

    row_alice_shared_key = Frame(row_alice)
    lbl_alice_shared_key = Label(row_alice_shared_key, text="Shared key Alice: ")
    lbl_alice_shared_key_result = Label(row_alice_shared_key, text="", fg="green")
    btn_alice_shared_key = Button(row_alice_shared_key, text="Get", command=get_shared_key_alice, width = 4, height = 1)
    row_alice_cipher = Frame(row_alice)
    lbl_cipher_alice = Label(row_alice_cipher, text="Message")
    cipher_alice_input = Entry(row_alice_cipher,width=20, fg="green")
    btn_alice_decrypt = Button(row_alice_cipher, text="Decrypt", command=decrypt_alice_message, width = 6, height = 1)
    lbl_message_alice = Label(row_alice, text="", fg="green")

    row_alice.pack(side=LEFT,padx = 5 , pady = 5, expand = YES)
    lbl_alice.pack()
    row_alice_private_key.pack()
    lbl_alice_private_key.pack(side=LEFT)
    private_alice_input.pack()
    
    row_alice_shared_key.pack()
    lbl_alice_shared_key.pack(side=LEFT)
    lbl_alice_shared_key_result.pack(side=LEFT)
    btn_alice_shared_key.pack(side=RIGHT)
    row_alice_cipher.pack()
    lbl_cipher_alice.pack(side=LEFT)
    cipher_alice_input.pack(side=LEFT)
    btn_alice_decrypt.pack(side=RIGHT)
    lbl_message_alice.pack()


    

    
    lbl_bob = Label(row_bob, text="Bob", fg="blue", font=("Courier-Bold", 20))
    lb_bob_private_key = "Private key: {}".format(bob_private_key)
    lbl_bob_private_key = Label(row_bob, text=lb_bob_private_key)

    row_bob_private_key = Frame(row_bob)
    lbl_bob_private_key = Label(row_bob_private_key, text="Private key: ")
    private_bob_input = Entry(row_bob_private_key, width=5,fg="blue", justify=CENTER)
    private_bob_input.insert(0, bob_private_key)

    row_bob_shared_key = Frame(row_bob)
    lbl_bob_shared_key = Label(row_bob_shared_key, text="Shared key Bob: ")
    lbl_bob_shared_key_result = Label(row_bob_shared_key, text="", fg="blue")
    btn_bob_shared_key = Button(row_bob_shared_key, text="Get", command=get_shared_key_bob, width = 4, height = 1)
    row_bob_cipher = Frame(row_bob)
    lbl_cipher_bob = Label(row_bob_cipher, text="Message")
    cipher_bob_input = Entry(row_bob_cipher,width=20, fg="blue")
    btn_bob_decrypt = Button(row_bob_cipher, text="Decrypt", command=decrypt_bob_message, width = 6, height = 1)
    lbl_message_bob = Label(row_bob, text="", fg="blue")

    
    row_bob.pack(side=RIGHT,padx = 5 , pady = 5, expand = YES)
    lbl_bob.pack()
    row_bob_private_key.pack()
    lbl_bob_private_key.pack(side=LEFT)
    private_bob_input.pack()
    row_bob_shared_key.pack()
    lbl_bob_shared_key.pack(side=LEFT)
    lbl_bob_shared_key_result.pack(side=LEFT)
    btn_bob_shared_key.pack(side=RIGHT)
    row_bob_cipher.pack()
    lbl_cipher_bob.pack(side=LEFT)
    cipher_bob_input.pack(side=LEFT)
    btn_bob_decrypt.pack(side=RIGHT)
    lbl_message_bob.pack()
    

    
    
    row5 = Frame(window)
    msg_input = Entry(row5,width=50, bg="yellow")
    msg_input.insert(0, "Đây là một thông điệp!!!")
    btn_encrypt = Button(row5, text="Send Alice", command=send_alice_btn_press, width = 25, height = 2, fg="green")
    btn_decrypt = Button(row5, text="Send Bob", command=send_bob_btn_press, width = 25, height = 2, fg="blue")
    row5.pack(padx = 5 , pady = 5)
    msg_input.pack()
    btn_encrypt.pack(side = LEFT)
    btn_decrypt.pack(side = RIGHT)

    auth = Label(window, text="Author: Chu Van Hung")
    auth.config(font =("Courier", 11), fg="red")
    # auth.pack(side = BOTTOM, anchor=SE)
    window.mainloop()



create_ui()
