import argparse

def xor_cypher(input_data, key):
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(input_data)])

def xor_encrypt_decrypt_file(input_file, output_file, key):
    with open(input_file, 'rb') as f:
        data = f.read()

    key = bytes(key, encoding='utf8')
    encrypted_data = xor_cypher(data, key)

    with open(output_file, 'wb') as f:
        f.write(encrypted_data)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="XOR encrypt/decrypt a file.")
    parser.add_argument("input_file", help="The path to the input file.")
    parser.add_argument("output_file", help="The name of the output file.")
    parser.add_argument("key", help="The XOR key.")
    args = parser.parse_args()
    
    xor_encrypt_decrypt_file(args.input_file, args.output_file, args.key)

