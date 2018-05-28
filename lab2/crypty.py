from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Cipher import DES3
from Crypto.Util import Padding
from Crypto.PublicKey import RSA
from Crypto.PublicKey import ElGamal
from Crypto.Cipher import PKCS1_v1_5 as cip_PKCS1
from Crypto.Signature import PKCS1_v1_5 as sig_PKCS1
from Crypto.Hash import SHA1
from Crypto.Hash import SHA224
from Crypto.Hash import SHA256
from Crypto.Hash import SHA384
from Crypto.Hash import SHA512
from Crypto.Hash import SHA3_224
from Crypto.Hash import SHA3_256
from Crypto.Hash import SHA3_384
from Crypto.Hash import SHA3_512
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
        io_util.sym_alg_key_to_file(repr_file, "AES", self.key)

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

    def copy(self):
        obj = CryptyAES()
        obj.mode = self.mode
        obj.key_size = self.key_size
        obj.key = self.key
        obj.block_size = AES.block_size
        obj.iv = self.iv
        obj.cypher = AES.new(obj.key, obj.mode, obj.iv)
        return obj

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
        io_util.sym_alg_key_to_file(repr_file, "DES3", self.key)

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

    def copy(self):
        obj = CryptyDES3()
        obj.mode = self.mode
        obj.key_size = self.key_size
        obj.key = self.key
        obj.block_size = DES3.block_size
        obj.iv = self.iv
        obj.cypher = DES3.new(obj.key, obj.mode, obj.iv)
        return obj

class CryptyRSA:
    def __init__(self):
        self.name='RSA'
        self.key_sizes = {'1024': 1024, '2048': 2048, '4096': 4096}

    def init_with(self, key_size, repr_file='rsa.cry'):
        self.key_size = self.key_sizes[key_size]
        self.private_key = RSA.generate(self.key_size)
        self.public_key = self.private_key.publickey()
        io_util.rsa_key_to_file('pub_'+repr_file, self.public_key, self.key_size)
        io_util.rsa_key_to_file('priv_'+repr_file, self.private_key, self.key_size, private=True)

        self.sign_key = sig_PKCS1.new(self.private_key)
        self.verify_key = sig_PKCS1.new(self.public_key)
        self.private_key = cip_PKCS1.new(self.private_key)
        self.public_key = cip_PKCS1.new(self.public_key)

    def encrypt(self, input):
        return self.public_key.encrypt(input)

    def decrypt(self, cypher_text):
        sentinel = Random.new().read(15+len(cypher_text))
        return self.private_key.decrypt(cypher_text, sentinel)

    def sign(self, digest):
        return self.sign_key.sign(digest)

    def verify(self, digest, signature):
        return self.verify_key.verify(digest, signature)

class CryptyElGamal:
    def __init__(self):
        self.name='ElGamal'
        self.key_sizes = {'256': 256, '512': 512, '1024': 1024}

    def init_with(self, key_size, repr_file='elg.cry'):
        self.key_size = self.key_sizes[key_size]
        self.private_key = ElGamal.generate(self.key_size, Random.new().read)
        self.public_key = self.private_key.publickey()
        self.p = self.public_key.p
        io_util.elg_key_to_file('pub_'+repr_file, self.public_key, self.key_size)
        io_util.elg_key_to_file('priv_'+repr_file, self.private_key, self.key_size, private=True)

        self.sign_key = cip_PKCS1.new(self.private_key)
        self.verify_key = cip_PKCS1.new(self.public_key)
        self.private_key = cip_PKCS1.new(self.private_key)
        self.public_key = cip_PKCS1.new(self.public_key)

    def encrypt(self, input):
        self.public_key.encrypt(input)

    def decrypt(self, cypher_text):
        return self.private_key.decrypt(cypher_text)

    def sign(self, digest):
        return self.sign_key.sign(digest)

    def verify(self, digest, signature):
        return self.verify_key.verify(digest, signature)

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

    def update(self, input):
        self.obj.update(input)

    def digest(self, input):
        self.update(input)
        return self.obj.digest()

    def copy(self):
        hash = CryptySHA()
        hash.init_with(self.name)
        return hash

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

def load_asym_key(msg, repr_file):
    ans = io_util.read_arr_elem(["RSA", "ElGamal"], msg)
    cypher = None
    if ans == "RSA":
        cypher = CryptyRSA()
    else:
        cypher = CryptyElGamal()
    key_size = io_util.read_arr_elem(list(cypher.key_sizes.keys()), "Select key size")
    cypher.init_with(key_size=key_size, repr_file=repr_file)
    return cypher

def load_hash(msg):
    hash = CryptySHA()
    ans = io_util.read_arr_elem(list(hash.types.keys()), msg)
    hash.init_with(type=ans)
    return hash

def create_seal():
    print(io_util.welcome_msg())
    while True:
        input_file = io_util.read_word("Path to input file (or Enter for default 'input.txt')")
        input_file = "input.txt" if input_file == "" else input_file
        input = open(input_file, "r").read()
        input = bytes(input, 'utf-8')
        session_key = load_sym_key("Select algorithm for session key")
        sender_key = load_asym_key("Select public-key algorithm for sender", repr_file="sender.cry")
        receiver_key = load_asym_key("Select public-key algorithm for receiver", repr_file="receiver.cry")
        hash = load_hash("Select hashing algorithm")

        print("Generating envelope...")
        envelope_data = session_key.encrypt(input)
        envelope_crypted_key = receiver_key.encrypt(session_key.key)
        io_util.envelope_to_file(input_file, 'envelope.cry', session_key.name, receiver_key.name, session_key.key_size,
                             receiver_key.key_size, envelope_data, envelope_crypted_key)

        print("Generating signature...")
        hashed_envelope = hash.digest(envelope_data)
        signature = sender_key.sign(hash.obj)
        io_util.signature_to_file(input_file, 'signature.cry', hash.name, sender_key.name, hash.digest_len,
                              sender_key.key_size, signature)

        print("Decrypting...")
        decrypt_output_file = "decrypted_" + input_file
        decrypting_hash = hash.copy()
        decrypting_hash.update(envelope_data)
        print("Decrypted envelope hash matches received data's hash?", sender_key.verify(decrypting_hash.obj, signature))
        decrypted_session_key = sender_key.decrypt(envelope_crypted_key)
        decrypting_session_key = session_key.copy()
        decrypted_data = decrypting_session_key.decrypt(envelope_data)
        print("Decrypted content matches input?", input.decode('utf-8') == decrypted_data.decode('utf-8'))
        with open(decrypt_output_file, 'w') as output_file:
            output_file.write(decrypted_data.decode('utf-8'))
        print("Wrote decrypted content to file", decrypt_output_file)

if __name__ == '__main__':
    create_seal()