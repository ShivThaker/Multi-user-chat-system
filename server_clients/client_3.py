import socket
import hashlib
from juice import des, en_de_functions, reformat_length

# --parity bit drop table
keyp = [57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4]


key = "AF0B00028736BCF5"
key = des.hex2bin(key)
key = des.permute(key, keyp, 56)

# Splitting
left = key[0:28]  # rkb for RoundKeys in binary
right = key[28:56]  # rbk_2 for RoundKeys in hexadecimal

rkb = []
rbk_2 = []
for i in range(0, 16):
    # Shifting the bits by nth shifts by checking from shift table
    left = des.shift_left(left, des.shift_table[i])
    right = des.shift_left(right, des.shift_table[i])

    # Combination of left and right string
    combine_str = left + right

    # Compression of key from 56 to 48 bits
    round_key = des.permute(combine_str, des.key_comp, 48)

    rkb.append(round_key)
###################################################################


s = socket.socket()
host = '127.0.0.1'
port = 9999
ser_pub_key = ()

s.connect((host, port))  # creates a tuple
print('PLS use the hexadecimal data-set i.e. [0-9-A-F]')
name = input('Client name: ')
s.send(str.encode(name))
# s.send(str.encode(f'|{d}|{m}|'))

print('Linked to server | Waiting for server to initiate the chat')

while True:
    try:
        data = s.recv(1024)  # 1024 is the buffer size
        data = data[:].decode("utf-8")

        if data == 'SERVER DISCONNECTED':
            print('\nSERVER DISCONNECTED')
            continue
        if len(data) > 0 and data[0] != '|':
            if data == ' ':
                s.send(str.encode(data))
            else:
                data = en_de_functions.decrypt(data, ser_pub_key)
                print(f'server> {data}')
                inp = input(f'{name}> ')
                inp = reformat_length._16_bit_len(inp)  # reformat the string to 16 byte length for DES decryption
                # and encryption

                inp = des.bin2hex(des.encrypt(inp, rkb))
                result = hashlib.sha256(inp.encode())   # 32 byte fixed length of 64 hexadecimal chars
                final_msg = inp + '|||' + result.hexdigest()
                s.send(str.encode(str(final_msg)))

        if data[0] == '|':
            data = data.split('|')
            print('\nServer Public Key received!')
            ser_pub_key = (data[1], data[2])
            print(ser_pub_key)
            rbk_2 = reformat_length.client_key_transfer(rkb[::-1])
            rbk_2 = en_de_functions.encrypt(rbk_2, ser_pub_key)
            s.send(str.encode(rbk_2))
            print('Des key encrypted and sent to server.\nSERVER CONNECTED\n')
    except KeyError as err:
        print(err)
        print("** ERROR - Input character out of data-set limit **")
        break
    except ConnectionResetError as err:
        print(err)
        print("** ERROR - Server RESET | Try connecting again **")
        break