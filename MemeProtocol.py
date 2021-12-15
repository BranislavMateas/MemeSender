import tkinter as tk
import tkinter.scrolledtext as tkscrolled

# WINDOW AND FRAMES SETUP
# window setup
ws = tk.Tk()
ws.title("Meme sender")
ws.geometry("1200x600")
ws.resizable(False, False)
ws.configure(background='#34393E')

# CREDITENTIALS FRAME
# left frame with creditentials input
left_cred = tk.Frame(ws, background="#34393E", width=550, height=60)
left_cred.grid(row=0, column=0, rowspan=2, sticky="nw", padx=20, pady=20)
left_cred.grid_propagate(0)

# ip part
ip_label = tk.Label(left_cred, text="IP address:", background="#34393E", font=("Helvetica", 12, "bold"), fg="#FDCB52")
ip_label.grid(row=0, column=0, sticky='nsew', padx=3)

ip_input = tk.Entry(left_cred, width=50, font=("Helvetica", 12))
ip_input.grid(row=0, column=1)

# nickaname part
nick_label = tk.Label(left_cred, text="Nickname:", background="#34393E", font=("Helvetica", 12, "bold"), fg="#FDCB52")
nick_label.grid(row=1, column=0, sticky='w', pady=10, padx=3)

nick_input = tk.Entry(left_cred, width=50, font=("Helvetica", 12))
nick_input.grid(row=1, column=1)


# right frame with creditentials input
right_cred = tk.Frame(ws, background="#34393E", width=550, height=60)
right_cred.grid(row=0, column=1, rowspan=2, sticky="nw", padx=20, pady=20)
right_cred.grid_propagate(0)

# port part
port_label = tk.Label(right_cred, text="Port Num.:", background="#34393E", font=("Helvetica", 12, "bold"), fg="#FDCB52")
port_label.grid(row=0, column=0, sticky='w', padx=3)

port_input = tk.Entry(right_cred, width=50, font=("Helvetica", 12))
port_input.grid(row=0, column=1)

# nickaname part
pass_label = tk.Label(right_cred, text="Password:", background="#34393E", font=("Helvetica", 12, "bold"), fg="#FDCB52")
pass_label.grid(row=1, column=0, sticky='w', pady=10, padx=3)

pass_input = tk.Entry(right_cred, width=50, font=("Helvetica", 12))
pass_input.grid(row=1, column=1)


# MEME DETATAILS FRAME
meme_frame = tk.Frame(ws, background="#34393E", width=1150, height=200)
meme_frame.grid(row=3, column=0, columnspan=2, sticky="n", padx=22)
meme_frame.grid_propagate(0)

# description part
desc_label = tk.Label(meme_frame, text="Description:", background="#34393E", font=("Helvetica", 12, "bold"), fg="#FDCB52")
desc_label.grid(row=0, column=0, sticky='w')

desc_input = tk.scrolledtext.ScrolledText(meme_frame, width=102, height=5, font=("Helvetica", 14))
desc_input.grid(row=1, column=0, sticky='w', padx=3, pady=2)

nsfw_check = tk.Checkbutton(meme_frame, text="is NSFW (Not safe for work)", background="#34393E", font=("Helvetica", 12, "bold"), fg="#FDCB52", activebackground="#34393E", activeforeground="#FDCB52", bd=0, disabledforeground="#FDCB52")
nsfw_check.grid(row=2, column=0, sticky='w', padx=3, pady=2)


# BUTTONS AND PROGRESS BAR FRAME
upload_frame = tk.Frame(ws, background="#fff", width=1144, height=200)
upload_frame.grid(row=5, column=0, columnspan=2, sticky="n", pady=10)
upload_frame.grid_propagate(0)


# RUN THE APP MAINLOOP
ws.mainloop()









"""

import socket
import pynetstring
import base64

decoder = pynetstring.Decoder()

def main():
    HOST = '159.89.4.84'  # The server's hostname or IP address
    TEST_PORT = 42070  # The port used by the server
    # PORT = 42069        # The port used by the server
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, TEST_PORT))
        s.sendall(pynetstring.encode('C MTP V:1.0'))

        data = s.recv(1024)

        if pynetstring.decode(data) == [b'S MTP V:1.0']:
            print('Connection Successful')
        else:
            print('Connection Failed')


        # nick part
        nick = input('Enter your nickname: ')
        s.sendall(pynetstring.encode(b'C ' + bytes(nick, 'utf-8')))

        # receiving token
        TOKEN_MESSAGE = pynetstring.decode(s.recv(1024))
        for i in TOKEN_MESSAGE:
            TOKEN = str(i.decode('utf-8')[2:])

        print(f"Token: {TOKEN}")

        # getting port number
        PORT_MESSAGE = pynetstring.decode(s.recv(1024))
        for i in PORT_MESSAGE:
            DATA_PORT = int(i.decode('utf-8')[2:])

        print(f"Port: {DATA_PORT}")


        # connecting to dataChannel
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as dataChannel:
            dataChannel.connect((HOST, DATA_PORT))

            # sending nick
            dataChannel.sendall(pynetstring.encode(b'C ' + bytes(nick, 'utf-8')))

            # receiving token
            TOKEN_MESSAGE = pynetstring.decode(dataChannel.recv(1024))
            for i in TOKEN_MESSAGE:
                CHECK_TOKEN = str(i.decode('utf-8')[2:])

            # checking token validity
            if CHECK_TOKEN == TOKEN:
                print('Token Match')
            else:
                print(f'Token Mismatch, token received: {CHECK_TOKEN}')

            # data
            for i in range(4):
                data = pynetstring.decode(dataChannel.recv(1024))[0]
                
                if data == b'S REQ:meme':
                    # sending data
                    base64string = base64.b64encode(open("./images/Meme.png", "rb").read()).decode("ascii")
                    dataChannel.sendall(pynetstring.encode(b'C ' + bytes(base64string, "ascii")))

                    # retrieving datalength returned by the server
                    print(f"Meme sent successfully: {pynetstring.decode(dataChannel.recv(1024))}")

                elif data == b'S REQ:description':
                    # sending data
                    dataChannel.sendall(pynetstring.encode(b'C ' + bytes('This is a meme', 'utf-8')))

                    # retrieving datalength returned by the server
                    print(f"Description sent successfully: {pynetstring.decode(dataChannel.recv(1024))}")

                elif data == b'S REQ:isNSFW':
                    # sending data
                    dataChannel.sendall(pynetstring.encode(b'C ' + bytes('true', 'utf-8')))

                    # retrieving datalength returned by the server
                    print(f"NSFW status sent successfully: {pynetstring.decode(dataChannel.recv(1024))}")

                elif data == b'S REQ:password':
                    # sending data
                    dataChannel.sendall(pynetstring.encode(b'C ' + bytes('password', 'utf-8')))

                    # retrieving datalength returned by the server
                    print(f"Password sent successfully: {pynetstring.decode(dataChannel.recv(1024))}")

                else:
                    print(f"Request unknown, retrieving dtoken")
                    break

            # retrieving dtoken
            DTOKEN_RAW = pynetstring.decode(dataChannel.recv(1024))
            for i in DTOKEN_RAW:
                DTOKEN = str(i.decode('utf-8')[2:])
            DTOKEN = DTOKEN[4:]

            # checking token difference
            if DTOKEN == TOKEN:
                print('Dtoken verification failed, something unexpected happened')
                return 

            print(f"Dtoken verification successful: {DTOKEN}")
            # RETURNING TO MAIN CHANNEL

        # catching msglen
        msglen = pynetstring.decode(s.recv(1024))[0]
        print(f"Message length: {msglen}")

        # sending server dtoken
        print(DTOKEN)
        s.sendall(pynetstring.encode(b'C ' + bytes(DTOKEN, "utf-8")))

        # ending the connection
        data = pynetstring.decode(s.recv(1024))[0]
        if data == b'S ACK':
            print('Connection ended')

        else:
            print(f'Connection end failed: {data}')
            return


if __name__ == '__main__':
    main()


"""














