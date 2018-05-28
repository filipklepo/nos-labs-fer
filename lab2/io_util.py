import sys
import re
import base64

REPR_MAX_LINE_LENGTH = 60

def welcome_msg():
    return '''
   _____                  _         
  / ____|                | |        
 | |     _ __ _   _ _ __ | |_ _   _ 
 | |    | '__| | | | '_ \| __| | | |
 | |____| |  | |_| | |_) | |_| |_| |
  \_____|_|   \__, | .__/ \__|\__, |
               __/ | |         __/ |
              |___/|_|        |___/  v0.1.1
              
Welcome to Crypty, a tool for generating electronic seal.
'''

def _chunks(list, n):
    result = []
    for i in range(len(list) // n + 1):
        if i*n == len(list):
            break
        result.append(list[i*n:(i+1)*n] if (i+1)*n <= len(list) else list[i*n:])
    return result

def _adjust_str_for_repr(str):
    return '\n'.join(['    ' + chunk for chunk in _chunks(str, REPR_MAX_LINE_LENGTH)])

def read_arr_elem(arr, mesg):
    ans = ""
    print(mesg+':')
    for i in range(len(arr)):
        print('    {}) {}'.format(i+1, arr[i]))
    while len(ans) == 0 or re.match(r'^\d+$', ans) is None or int(ans) > len(arr):
        print("> ", end="", flush=True)
        ans = sys.stdin.readline().strip()
    return arr[int(ans)-1]

def read_word(mesg):
    print(mesg+': ', end="", flush=True)
    return sys.stdin.readline().strip()

def sym_alg_to_file(input_filename, method, data, output_filename, description="Crypted file"):
    formatted_data = _adjust_str_for_repr(data)

    with open(output_filename, 'w') as f:
        f.write('''---BEGIN NOS CRYPTO DATA---
Description:
    {desc}

Method:
    {method}

File name:
    {input_file}

Data:
{formatted_data}

---END NOS CRYPTO DATA---

'''.format(desc=description, method=method, input_file=input_filename, formatted_data=formatted_data))

def sym_alg_key_to_file(output_filename, method, key, description="Secret key"):
    key = _adjust_str_for_repr(key.hex())
    with open(output_filename, 'w') as f:
        f.write('''---BEGIN NOS CRYPTO DATA---
Description:
    {desc}

Method:
    {method}

Secret key:
{key}

---END NOS CRYPTO DATA---

'''.format(desc=description, method=method, key=key))

def _int_to_hex_str_padded(num):
    repr = hex(num)[2:]
    nearest_e_2 = 1
    while nearest_e_2 < len(repr):
        nearest_e_2 *= 2
    if nearest_e_2 != len(repr):
        repr = '0' * (nearest_e_2-len(repr)) + repr
    return repr

def rsa_key_to_file(output_filename, rsa_key, key_size, private=False, description=""):
    repr_prefix = "Public "
    if private:
        repr_prefix = "Private "
    if description == "":
        description = repr_prefix + "key"
    key_length = _int_to_hex_str_padded(key_size)

    modulus_repr = _adjust_str_for_repr(hex(rsa_key.n)[2:])
    exponent_repr = ""
    if not private:
        exponent_repr = _adjust_str_for_repr(hex(rsa_key.e)[2:])
    else:
        exponent_repr = _adjust_str_for_repr(hex(rsa_key.d)[2:])

    with open(output_filename, 'w') as f:
        f.write('''---BEGIN NOS CRYPTO DATA---
Description:
    {description}

Method:
    RSA

Key length:
    {key_length}

Modulus:
{modulus_repr}

{repr_prefix}exponent:
{exponent_repr}

---END NOS CRYPTO DATA---
'''.format(description=description, key_length=key_length, modulus_repr=modulus_repr,
           repr_prefix=repr_prefix, exponent_repr=exponent_repr))

def elg_key_to_file(output_filename, elg, key_size, private=False, description=""):
    repr_prefix = "Public "
    if private:
        repr_prefix = "Private "
    if description == "":
        description = repr_prefix + "key"
    key_length = _int_to_hex_str_padded(key_size)

    modulus_repr = _adjust_str_for_repr(hex(int(elg.p))[2:])
    generator_repr = _adjust_str_for_repr(hex(int(elg.g))[2:])

    with open(output_filename, 'w') as f:
        f.write('''---BEGIN NOS CRYPTO DATA---
Description:
    {description}

Method:
    ElGamal

Key length:
    {key_length}

Modulus:
{modulus_repr}

Generator:
{generator_repr}

---END NOS CRYPTO DATA---
'''.format(description=description, key_length=key_length, modulus_repr=modulus_repr,
           generator_repr=generator_repr))

def signature_to_file(input_filename, output_filename, hash, asym_algo, hash_len, asym_key_len,signature):
    signature = _adjust_str_for_repr(signature.hex())
    with open(output_filename, 'w') as f:
        f.write('''---BEGIN NOS CRYPTO DATA---
Description:
    Signature

File name:
    {input_filename}

Method:
    {hash}
    {asym_algo}

Key length:
    {hash_len}
    {asym_key_len}

Signature:
{signature}

---END NOS CRYPTO DATA---
'''.format(input_filename=input_filename, hash=hash,asym_algo=asym_algo,
           hash_len=_int_to_hex_str_padded(hash_len), asym_key_len=_int_to_hex_str_padded(asym_key_len), signature=signature))

def envelope_to_file(input_filename, output_filename, sym_algo, asym_algo, sym_key_len, asym_key_len, data,
                     sym_key):
    data = _adjust_str_for_repr(base64.b64encode(data).decode('utf-8'))
    sym_key = _adjust_str_for_repr(sym_key.hex())
    with open(output_filename, 'w') as f:
        f.write('''---BEGIN NOS CRYPTO DATA---
Description:
    Envelope

File name:
    {input_filename}

Method:
    {sym_algo}
    {asym_algo}

Key length:
    {sym_key_len}
    {asym_key_len}

Envelope data:
{data}

Envelope crypt key:
{sym_key}

---END NOS CRYPTO DATA---
'''.format(input_filename=input_filename, sym_algo=sym_algo, asym_algo=asym_algo,
                   sym_key_len=_int_to_hex_str_padded(sym_key_len), asym_key_len=_int_to_hex_str_padded(asym_key_len),
                   data=data, sym_key=sym_key))