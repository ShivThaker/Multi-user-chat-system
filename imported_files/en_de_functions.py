from imported_files import rsa


def encrypt(data, private):
    """
     Encrypts incoming data with given private key
     """
    # print("private key used:", private)
    encrypted_data = ""
    for i in range(0, len(data)):
        encrypted_data += str(rsa.endecrypt(ord(data[i]), private[0], private[1])) + ","
    return encrypted_data


def decrypt(data, public):
    """
     Decrypts input integer list into sentences
     """
    # print("Decrypting")
    words = data.split(",")
    decrypted_data = ""
    for i in range(0, len(words) - 1):
        decrypted_data += str(rsa.decode(rsa.endecrypt(words[i], public[0], public[1])))
    decrypted_data = decrypted_data.replace("'b'", "")
    decrypted_data = decrypted_data.replace("b'", "")
    decrypted_data = decrypted_data.replace("'", "")
    # print("Decrypted Data: ",decrypted_data)
    return decrypted_data

"""
a=encrypt('aaa',(43,247))
print(a)
b=decrypt(a,(211,247))
print(b)
"""