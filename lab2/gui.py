from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Cipher import DES3
from Crypto.Util import Padding
import base64

def aes():
    input = "filipjelegendafilipjelegendafilipjelegendafilipjelegenda"

    #---PICKER
    aes_modes = {
        'MODE_CBC': AES.MODE_CBC,
        'MODE_CFB': AES.MODE_CFB,
        'MODE_OFB': AES.MODE_OFB}
    aes_key_sizes = {'AES-128': 16, 'AES-192': 24, 'AES-256': 32}

    #---CHOOSER
    aes_mode = aes_modes['MODE_CBC']
    key_size = aes_key_sizes['AES-192']
    key = Random.new().read(key_size)
    block_size = AES.block_size
    iv = Random.new().read(block_size)
    cypher = AES.new(key, aes_mode, iv)

    #---ENCRYPT
    input = bytes(input, 'utf-8')
    input = Padding.pad(input, block_size)
    output = b''
    for i in range(len(input) // block_size):
        output += cypher.encrypt(input[i*block_size:(i+1)*block_size])
    output = base64.b64encode(output)

    #--DECRYPT
    enc = output
    enc = base64.b64decode(enc)

    decypher = AES.new(key, aes_mode, iv)
    decrypted_output = b''
    for i in range(len(enc) // block_size):
        decrypted_output += decypher.decrypt(enc[i*block_size:(i+1)*block_size])
    # decrypted_output = Padding.unpad(decrypted_output, block_size)
    print("Decrypted content:", decrypted_output)
    print("Success:", input == decrypted_output)

    #ASYMMETRIC: RSA and ElGamal for asymetric (3 different key sizes)
    #HASH: SHA-1 as hash function (SHA1-256, SHA1-512, ..)

def three_des():
    input = "filipjelegendafilipjelegendafilipjelegendafilipjelegenda"

    # ---PICKER
    des_modes = {
        'MODE_CBC': DES3.MODE_CBC,
        'MODE_CFB': DES3.MODE_CFB,
        'MODE_OFB': DES3.MODE_OFB}
    des_key_sizes = {'16': 16, '24': 24}

    # ---CHOOSER
    des_mode = des_modes['MODE_CBC']
    key_size = des_key_sizes['16']
    key = Random.new().read(key_size)
    block_size = DES3.block_size
    iv = Random.new().read(block_size)
    cypher = DES3.new(key, des_mode, iv)

    # ---ENCRYPT
    input = bytes(input, 'utf-8')
    input = Padding.pad(input, block_size)
    output = b''
    for i in range(len(input) // block_size):
        output += cypher.encrypt(input[i * block_size:(i + 1) * block_size])
    output = base64.b64encode(output)

    #--DECRYPT
    enc = output
    enc = base64.b64decode(enc)

    decypher = DES3.new(key, des_mode, iv)
    decrypted_output = b''
    for i in range(len(enc) // block_size):
        decrypted_output += decypher.decrypt(enc[i*block_size:(i+1)*block_size])
    # decrypted_output = Padding.unpad(decrypted_output, block_size)
    print("Decrypted content:", decrypted_output)
    print("Success:", input == decrypted_output)


#If there's time left:
#
# class CryptoGui:
#     def __init__(self, master):
#         self.master = master
#         master.title("Crypto util")
#
#         self.label = Label(master, text="Crypto util!")
#         self.label.pack()
#
#         self.submit_button = Button(master, text="Submit", command=self.submit)
#         self.submit_button.pack()
#
#         self.close_button = Button(master, text="Close", command=master.quit)
#         self.close_button.pack()
#
#     def submit(self):
#         print("Submitted")

# root_tk = Tk()
# crypto_gui = CryptoGui(root_tk)
# root_tk.mainloop()
three_des()