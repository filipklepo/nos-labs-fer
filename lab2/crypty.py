from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Cipher import DES3
from Crypto.Util import Padding
from Crypto.PublicKey import RSA
from Crypto.PublicKey import ElGamal
import base64
import repr_file_util
from random import randint

class CryptyAES:
    def __init__(self):
        self.modes = {
        'MODE_CBC': AES.MODE_CBC,
        'MODE_CFB': AES.MODE_CFB,
        'MODE_OFB': AES.MODE_OFB}
        self.key_sizes = {'128': 16, '192': 24, '256': 32}

# metode po potrebi

class CryptyDES3:
    def __init__(self):
        self.modes = {
            'MODE_CBC': DES3.MODE_CBC,
            'MODE_CFB': DES3.MODE_CFB,
            'MODE_OFB': DES3.MODE_OFB}
        self.key_sizes = {'16': 16, '24': 24}

class CryptyRSA:
    def __init__(self):
        self.key_sizes = [1024, 2048, 4096]

class CryptyElGamal:
    def __init__(self):
        self.key_sizes = [256, 512, 1024]

#############################
#######
## SYMMETRIC
######
#############################

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

#############################
#######
## ASYMMETRIC (RSA and ElGamal)
######
#############################
## 3 different key sizes

def rsa():
    rsa_key_sizes = [1024, 2048, 4096]
    key_size = rsa_key_sizes[1]
    private_key = RSA.generate(key_size)
    public_key = private_key.publickey()
    input = "filip filip filip filip filip"
    input = bytes(input, 'utf-8')
    ciphtext = public_key.encrypt(input, "0")
    deciphertext = private_key.decrypt(ciphtext)
    print(input == deciphertext)

def el_gamal():
    elg_key_sizes = [256, 512, 1024]
    key_size = 256
    private_key = ElGamal.generate(key_size, Random.new().read)
    public_key = private_key.publickey()
    repr_file_util.elg_key_to_file("elgpub.pem", private_key)
    repr_file_util.elg_key_to_file("elgpriv.pem", public_key, private=True)
    input = "filip filip filip filip filip"
    input = bytes(input, 'utf-8')
    ciphtext = public_key.encrypt(input, randint(1, public_key.p-2))
    deciphertext = private_key.decrypt(ciphtext)
    print(input == deciphertext)

el_gamal()