import tkinter as tk
from tkinter import filedialog
from tkinter import scrolledtext
from tkinter import ttk
from tkinter import messagebox
import socket
from tkinter.constants import DISABLED
from tkinter.font import NORMAL
import pynetstring
import base64
import threading
import time
from tkinter import *


# WINDOW AND FRAMES SETUP
# window setup
ws = tk.Tk()
ws.title("Meme sender")
ws.geometry("1200x580")
ws.resizable(False, False)
ws.configure(background='#34393E')

# netstrings decoder initialization
decoder = pynetstring.Decoder()

# MAIN FUNCTION
def meme_post():
    # setting up the fields
    progress_text.config(state=NORMAL)
    progress_text.delete('1.0', END)
    progress_text.config(state=DISABLED)

    progress_bar["value"] = 0
    progress_percent.config(text="0%")
    ws.update_idletasks()

    ip = ip_input.get()
    port = port_input.get()

    # checking if ip and port fields are empty
    if ip == "" or port == "":
        progress_text.config(state=NORMAL)
        progress_text.insert(tk.END, "IP or PORT not filled" + "\n")
        progress_text.config(state=DISABLED)

        return

    try:
        # connecting to server
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        threading.Thread(target=s.connect((ip, int(port)))).start()
        
    except ConnectionRefusedError:
        progress_bar["value"] = 0
        progress_percent.config(text="0%")

        progress_text.config(state=NORMAL)
        progress_text.insert(tk.END, "Connection refused by server" + "\n")
        progress_text.config(state=DISABLED)

        return

    except TimeoutError:
        progress_bar["value"] = 0
        progress_percent.config(text="0%")

        progress_text.config(state=NORMAL)
        progress_text.insert(tk.END, "Connection timed out" + "\n")
        progress_text.config(state=DISABLED)
        
        return

    except (socket.gaierror, ValueError):
        progress_bar["value"] = 0
        progress_percent.config(text="0%")

        progress_text.config(state=NORMAL)
        progress_text.insert(tk.END, "Invalid IP or PORT" + "\n")
        progress_text.config(state=DISABLED)

        return
        
    progress_text.config(state=NORMAL)
    progress_text.insert(tk.END, "Server reached, initializating connection" + "\n")
    progress_text.config(state=DISABLED)

    # adding progress
    threading.Thread(target=progress_bar_add(5)).start()

    # sending server initializating message
    s.sendall(pynetstring.encode('C MTP V:1.0'))
    data = s.recv(1024)

    # checking if correct message was received
    if pynetstring.decode(data) == [b'S MTP V:1.0']:
        threading.Thread(target=progress_bar_add(5)).start()
    
        progress_text.config(state=NORMAL)
        progress_text.insert(tk.END, "Connection initialized: " + ip + ":" + port + "\n")
        progress_text.config(state=DISABLED)

    else:
        progress_bar["value"] = 0
        progress_percent.config(text="0%")

        s.sendall(pynetstring.encode('E Expected message not received (S MTP V:1.0)'))

        progress_text.config(state=NORMAL)
        progress_text.insert(tk.END, "Connection failed: " + pynetstring.decode(data)[0] + "\n")
        progress_text.config(state=DISABLED)

        return

    nick = nick_input.get()

    # checking if nick field is empty
    if nick == "":
        progress_bar["value"] = 0
        progress_percent.config(text="0%")

        # sending server error message
        s.sendall(pynetstring.encode('E Nick not filled'))

        progress_text.config(state=NORMAL)
        progress_text.insert(tk.END, "Nick not filled" + "\n")
        progress_text.config(state=DISABLED)

        return

    # sending nick to server
    s.sendall(pynetstring.encode('C ' + nick))

    # receiving server security token
    data = s.recv(1024)
    TOKEN = pynetstring.decode(data)[0]

    # checking token validity
    TOKEN = TOKEN.decode('utf-8')

    if TOKEN[0:2] != "S " or len(TOKEN) < 3:
        progress_bar["value"] = 0
        progress_percent.config(text="0%")

        s.sendall(pynetstring.encode('E Received token is not valid'))

        progress_text.config(state=NORMAL)
        progress_text.insert(tk.END, "Invalid token received" + "\n")
        progress_text.config(state=DISABLED)

        return

    threading.Thread(target=progress_bar_add(5)).start()

    # receiving port number from the server
    data = s.recv(1024)
    PORT = pynetstring.decode(data)[0]

    # checking port validity
    PORT = PORT.decode('utf-8')

    if PORT[0:2] != "S " or len(PORT) < 3:
        progress_bar["value"] = 0
        progress_percent.config(text="0%")

        s.sendall(pynetstring.encode('E Received message was not expected'))

        progress_text.config(state=NORMAL)
        progress_text.insert(tk.END, "Unexpected message from the server" + "\n")
        progress_text.config(state=DISABLED)

        return
    
    else:
        try:
            PORT = int(PORT[2:])

            progress_text.config(state=NORMAL)
            progress_text.insert(tk.END, "Port received: " + str(PORT) + "\n")
            progress_text.config(state=DISABLED)

            threading.Thread(target=progress_bar_add(5)).start()

        except ValueError:
            progress_bar["value"] = 0
            progress_percent.config(text="0%")

            s.sendall(pynetstring.encode('E Computer expected port number or received port is not valid'))

            progress_text.config(state=NORMAL)
            progress_text.insert(tk.END, "Invalid port message received" + "\n")
            progress_text.config(state=DISABLED)

            return


# "adding progress" to progress bar
def progress_bar_add(progress):
    for i in range(progress):
        progress_bar["value"] += 1
        progress_bar.update()
        progress_percent.config(text=str(int(progress_bar["value"])) + "%")
        time.sleep(0.1)







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
meme_frame = tk.Frame(ws, background="#34393E", width=1150, height=185)
meme_frame.grid(row=3, column=0, columnspan=2, sticky="n", padx=22)
meme_frame.grid_propagate(0)

# description part
desc_label = tk.Label(meme_frame, text="Description:", background="#34393E", font=("Helvetica", 12, "bold"), fg="#FDCB52")
desc_label.grid(row=0, column=0, sticky='w')

desc_input = tk.scrolledtext.ScrolledText(meme_frame, width=102, height=5, font=("Helvetica", 14))
desc_input.grid(row=1, column=0, sticky='w', padx=3, pady=2)

nsfw_check = tk.Checkbutton(meme_frame, text="is NSFW (Not safe for work)", background="#34393E", font=("Helvetica", 12, "bold"), highlightbackground="#34393E", fg="#FDCB52", activebackground="#34393E", activeforeground="#FDCB52", bd=0, disabledforeground="#FDCB52")
nsfw_check.grid(row=2, column=0, sticky='w', pady=2)


# BUTTONS AND PROGRESS BAR FRAME
upload_frame = tk.Frame(ws, background="#34393E", width=1144, height=260)
upload_frame.grid(row=5, column=0, columnspan=3, sticky="n", pady=10)
upload_frame.grid_propagate(0)

# upload meme from PC button
upload_button = tk.Button(upload_frame, text="Upload MEME from PC", width=20, background="#FDCB52", font=("Helvetica", 12, "bold"), fg="#34393E", activebackground="#34393E", activeforeground="#FDCB52")
upload_button.grid(row=0, column=0, sticky='w')

# post meme button
post_button = tk.Button(upload_frame, text="Post MEME", width=10, background="#FDCB52", font=("Helvetica", 12, "bold"), fg="#34393E", activebackground="#34393E", activeforeground="#FDCB52", command=meme_post)
post_button.grid(row=0, column=11, sticky='e')

# progress bar
progress_text = tk.Text(upload_frame, width=163, height=8, font=("Helvetica", 10), fg="#34393E", background="#BFBFBF", state="disabled")
progress_text.grid(row=1, rowspan=3, column=0, columnspan=12, sticky='wn', pady=20)

progress_bar = ttk.Progressbar(upload_frame, orient="horizontal", length=1144, mode="determinate")
progress_bar.grid(row=4, column=0, columnspan=12, sticky='wn')

progress_percent = tk.Label(upload_frame, text=str(int(progress_bar["value"])) + "%", background="#34393E", font=("Helvetica", 12, "bold"), fg="#FDCB52")
progress_percent.grid(row=5, column=0, sticky='w', pady=5)


# RUN THE APP MAINLOOP
ws.mainloop()





"""


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



"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # establishing connection with server
        try:
            s.connect((ip, int(port)))

            s.sendall(pynetstring.encode('C MTP V:1.0'))
            data = s.recv(1024)

            if pynetstring.decode(data) == [b'S MTP V:1.0']:
                progress_text.config(state=NORMAL)
                progress_text.insert(tk.END, "Connection initialized: " + ip + ":" + port + "\n")
                progress_text.config(state=DISABLED)
            else:
                progress_text.config(state=NORMAL)
                progress_text.insert(tk.END, "Connection failed: " + pynetstring.decode(data)[0] + "\n")
                progress_text.config(state=DISABLED)
                return

        except:
            pass        




# establishing connection
def establish_conn():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    ip = ip_input.get()
    port = port_input.get()

    if ip == "" or port == "":
        return False

    try:
        s.connect((ip, int(port)))

        s.sendall(pynetstring.encode('C MTP V:1.0'))

        

        if pynetstring.decode(data) == [b'S MTP V:1.0']:
            progress_text.config(state=NORMAL)
            progress_text.insert(tk.END, "Connection initialized: " + ip + ":" + port + "\n")
            progress_text.config(state=DISABLED)

        else:
            progress_text.config(state=NORMAL)
            progress_text.insert(tk.END, "Connection failed" + "\n")
            progress_text.config(state=DISABLED)

            return False
        
        return True

    except:
        return False 

# opening datachannel
def datachannel_setup():
    if nick_input.get() == "":
        return False
    else:
        s.sendall(pynetstring.encode(b'C ' + bytes(nick, 'utf-8')))


def initial_comm():
    pass


# turn image into base64
def image_compress():
    file = filedialog.askopenfilename(initialdir="/", title="Select file", filetypes=(("jpeg files", "*.jpeg"), ("png files", "*.png")))
    if file == "":
        progress_text.config(state=NORMAL)
        progress_text.insert(tk.END, "Import Cancelled" + "\n")
        progress_text.config(state=DISABLED)
        return False
    else:
        try:
            progress_text.config(state=NORMAL)
            progress_text.insert(tk.END, "Meme Loaded from PC: " + str(file) + "\n")
            progress_text.config(state=DISABLED)
            base64string = base64.b64encode(open(file, "rb").read()).decode("ascii")
            
            return True
        except:
            return False

"""











