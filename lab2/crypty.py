from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Cipher import DES3
from Crypto.Util import Padding
from Crypto.PublicKey import RSA
from Crypto.PublicKey import ElGamal
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA1
from Crypto.Hash import SHA224
from Crypto.Hash import SHA256
from Crypto.Hash import SHA384
from Crypto.Hash import SHA512
from Crypto.Hash import SHA3_224
from Crypto.Hash import SHA3_256
from Crypto.Hash import SHA3_384
from Crypto.Hash import SHA3_512
import base64
import io_util
from random import randint

class CryptyAES:
    def __init__(self):
        self.name = 'AES'
        self.modes = {
        'MODE_CBC': AES.MODE_CBC,
        'MODE_CFB': AES.MODE_CFB,
        'MODE_OFB': AES.MODE_OFB}
        self.key_sizes = {'128': 16, '192': 24, '256': 32}

    def init_with(self, mode, key_size, repr_file='aes.cry'):
        self.mode = self.modes[mode]
        self.key_size = self.key_sizes[key_size]

        self.key = Random.new().read(self.key_size)
        self.block_size = AES.block_size
        self.iv = Random.new().read(self.block_size)
        self.cypher = AES.new(self.key, self.mode, self.iv)

    def encrypt(self, input):
        input = Padding.pad(input, self.block_size)
        output = b''
        for i in range(len(input) // self.block_size):
            output += self.cypher.encrypt(input[i * self.block_size:(i + 1) * self.block_size])
        return output

    def decrypt(self, cypher_text):
        # decypher = AES.new(key, aes_mode, iv)
        decrypted_output = b''
        for i in range(len(cypher_text) // self.block_size):
            decrypted_output += self.cypher.decrypt(cypher_text[i * self.block_size:(i + 1) * self.block_size])
        return Padding.unpad(decrypted_output, self.block_size)

#AES and DES3 have identical encrypt and decrypt methods. Make them extend base class if theres time.

class CryptyDES3:
    def __init__(self):
        self.name='DES3'
        self.modes = {
            'MODE_CBC': DES3.MODE_CBC,
            'MODE_CFB': DES3.MODE_CFB,
            'MODE_OFB': DES3.MODE_OFB}
        self.key_sizes = {'16': 16, '24': 24}

    def init_with(self, mode, key_size, repr_file='des3.cry'):
        self.mode = self.modes[mode]
        self.key_size = self.key_sizes[key_size]

        self.key = Random.new().read(self.key_size)
        self.block_size = DES3.block_size
        self.iv = Random.new().read(self.block_size)
        self.cypher = DES3.new(self.key, self.mode, self.iv)

    def encrypt(self, input):
        input = Padding.pad(input, self.block_size)
        output = b''
        for i in range(len(input) // self.block_size):
            output += self.cypher.encrypt(input[i * self.block_size:(i + 1) * self.block_size])
        return output

    def decrypt(self, cypher_text):
        # decypher = DES3.new(key, des_mode, iv)
        decrypted_output = b''
        for i in range(len(cypher_text) // self.block_size):
            decrypted_output += self.cypher.decrypt(cypher_text[i * self.block_size:(i + 1) * self.block_size])
        return Padding.unpad(decrypted_output, self.block_size)

class CryptyRSA:
    def __init__(self):
        self.name='RSA'
        self.key_sizes = {'1024': 1024, '2048': 2048, '4096': 4096}

    def init_with(self, key_size, repr_file='rsa.cry'):
        self.key_size = self.key_sizes[key_size]
        self.private_key = RSA.generate(self.key_size)
        self.public_key = self.private_key.publickey()
        self.private_key = PKCS1_OAEP.new(self.private_key)
        self.public_key = PKCS1_OAEP.new(self.public_key)

    def encrypt(self, input, with_private_key=False):
        key = self.private_key if with_private_key else self.public_key
        ciphtext = key.encrypt(input)
        return ciphtext

    def decrypt(self, cypher_text):
        cypher_text = base64.b64decode(cypher_text)
        return self.private_key.decrypt(cypher_text)

class CryptyElGamal:
    def __init__(self):
        self.name='ElGamal'
        self.key_sizes = {'256': 256, '512': 512, '1024': 1024}

    def init_with(self, key_size, repr_file='rsa.cry'):
        self.key_size = self.key_sizes[key_size]
        self.private_key = ElGamal.generate(self.key_size, Random.new().read)
        self.public_key = self.private_key.publickey()

    def encrypt(self, input, with_private_key=False):
        input = bytes(input, 'utf-8')
        key = self.private_key if with_private_key else self.public_key
        ciphtext = key.encrypt(input, randint(1, self.public_key.p-2))
        return ciphtext

    def decrypt(self, cypher_text):
        cypher_text = base64.b64decode(cypher_text)
        return self.private_key.decrypt(cypher_text)

class CryptySHA:
    def __init__(self):
        self.types = {'SHA1': (SHA1, 160), 'SHA224': (SHA224, 224), 'SHA256': (SHA256, 256), 'SHA384': (SHA384, 384),
                      'SHA512': (SHA512, 512), 'SHA3_224': (SHA3_224, 224), 'SHA3_256': (SHA3_256, 256),
                      'SHA3_384': (SHA3_384, 384), 'SHA3_512': (SHA3_512, 512)}

    def init_with(self, type):
        self.name = type
        self.type, self.digest_len = self.types[type]
        self.obj = self.type.new()
        self.digest_size = self.obj.digest_size

    def digest(self, input):
        self.obj.update(input)
        return self.obj.digest()

def load_sym_key(msg):
    ans = io_util.read_arr_elem(["AES", "DES3"], msg)
    cypher = None
    if ans == "AES":
        cypher = CryptyAES()
    else:
        cypher = CryptyDES3()
    mode = io_util.read_arr_elem(list(cypher.modes.keys()), "Select mode")
    key_size = io_util.read_arr_elem(list(cypher.key_sizes.keys()), "Select key size")
    cypher.init_with(mode=mode, key_size=key_size)
    return cypher

def load_asym_key(msg):
    ans = io_util.read_arr_elem(["RSA", "ElGamal"], msg)
    cypher = None
    if ans == "RSA":
        cypher = CryptyRSA()
    else:
        cypher = CryptyElGamal()
    key_size = io_util.read_arr_elem(list(cypher.key_sizes.keys()), "Select key size")
    cypher.init_with(key_size=key_size)
    return cypher

def load_hash(msg):
    hash = CryptySHA()
    ans = io_util.read_arr_elem(list(hash.types.keys()), msg)
    hash.init_with(type=ans)
    return hash

def create_seal():
    io_util.welcome_msg()
    input_file = io_util.read_word("Path to input file (or Enter for default 'input.txt')")
    input_file = "input.txt" if input_file == "" else input_file
    input = open(input_file, "r").read()
    input = bytes(input, 'utf-8')
    session_key = load_sym_key("Select algorithm for session key")
    sender_key = load_asym_key("Select public-key algorithm for sender")
    receiver_key = load_asym_key("Select public-key algorithm for receiver")
    hash = load_hash("Select hashing algorithm")

    print("Generating envelope...")
    envelope_data = session_key.encrypt(input)
    envelope_crypted_key = receiver_key.encrypt(session_key.key)
    io_util.envelope_to_file(input_file, 'envelope.cry', session_key.name, receiver_key.name, session_key.key_size,
                             receiver_key.key_size, envelope_data, envelope_crypted_key)

    print("Generating signature...")
    hashed_envelope = hash.digest(envelope_data)
    signature = sender_key.encrypt(hashed_envelope, with_private_key=True)
    io_util.signature_to_file(input_file, 'signature.cry', hash.name, sender_key.name, hash.digest_len,
                             sender_key.key_size, signature)

if __name__ == '__main__':
    create_seal()