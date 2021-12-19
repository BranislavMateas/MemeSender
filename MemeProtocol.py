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
import os

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

    # checking if meme was imported
    if sel_file.cget("text") == "*No file selected":
        progress_text.config(state=NORMAL)
        progress_text.insert(tk.END, "No file selected" + "\n")
        progress_text.config(state=DISABLED)

        load_meme()

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

    TOKEN = TOKEN[2:]

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

    progress_text.config(state=NORMAL)
    progress_text.insert(tk.END, "Opening DataChannel connection" + "\n")
    progress_text.config(state=DISABLED)

    # establishing connection with the data channel
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as data_channel:
        try:
            data_channel.connect((ip, PORT))

            progress_text.config(state=NORMAL)
            progress_text.insert(tk.END, "DataChannel connection established" + "\n")
            progress_text.config(state=DISABLED)

            threading.Thread(target=progress_bar_add(5)).start()

        except Exception:
            progress_bar["value"] = 0
            progress_percent.config(text="0%")

            data_channel.sendall(pynetstring.encode('E DataChannel connection failed'))

            progress_text.config(state=NORMAL)
            progress_text.insert(tk.END, "Server did not opened the Data Channel" + "\n")
            progress_text.config(state=DISABLED)

            return

        # sending nick to the server in order to receive security token from the server
        data_channel.sendall(pynetstring.encode('C ' + nick))

        # receiving server security token
        data = data_channel.recv(1024)
        SEC_TOKEN = pynetstring.decode(data)[0]
        SEC_TOKEN = SEC_TOKEN.decode('utf-8')

        if SEC_TOKEN[0:2] != "S " or len(SEC_TOKEN) < 3:
            progress_bar["value"] = 0
            progress_percent.config(text="0%")

            s.sendall(pynetstring.encode('E Expected message not received (S <token>)'))

            progress_text.config(state=NORMAL)
            progress_text.insert(tk.END, "Unexpected message from the server, security token expected" + "\n")
            progress_text.config(state=DISABLED)

            return
        
        else:
            SEC_TOKEN = SEC_TOKEN[2:]

            progress_text.config(state=NORMAL)
            progress_text.insert(tk.END, "Security token received" + "\n")
            progress_text.config(state=DISABLED)

            threading.Thread(target=progress_bar_add(5)).start()

        if SEC_TOKEN != TOKEN:
            progress_bar["value"] = 0
            progress_percent.config(text="0%")

            s.sendall(pynetstring.encode('E Security token mismatch'))

            progress_text.config(state=NORMAL)
            progress_text.insert(tk.END, "Security token mismatch" + "\n")
            progress_text.config(state=DISABLED)

            return

        else:
            progress_text.config(state=NORMAL)
            progress_text.insert(tk.END, "Tokens verified" + "\n")
            progress_text.config(state=DISABLED)

            threading.Thread(target=progress_bar_add(5)).start()

        # DATA TRANSFER
        char_sum = 0

        while True:
            data = data_channel.recv(1024)
            data = pynetstring.decode(data)[0]

            # type of data
            if data == b'S REQ:meme':
                data_channel.sendall(pynetstring.encode('C ' + image))

                progress_text.config(state=NORMAL)
                progress_text.insert(tk.END, "Meme sent to the server" + "\n")
                progress_text.config(state=DISABLED)

                threading.Thread(target=progress_bar_add(5)).start()

                data = data_channel.recv(1024)
                data = pynetstring.decode(data)[0]
                data = data.decode('utf-8')

                if data[0:6] != "S ACK:":
                    progress_bar["value"] = 0
                    progress_percent.config(text="0%")

                    data_channel.sendall(pynetstring.encode('E Expected message not received (S ACK:<dataLength>)'))

                    progress_text.config(state=NORMAL)
                    progress_text.insert(tk.END, "Unexpected message from the server, ACK expected" + "\n")
                    progress_text.config(state=DISABLED)

                    return

                else:
                    data = data[6:]

                    try:
                        char_sum += int(data)

                    except ValueError:
                        progress_bar["value"] = 0
                        progress_percent.config(text="0%")

                        data_channel.sendall(pynetstring.encode('E DataLength not valid'))

                        progress_text.config(state=NORMAL)
                        progress_text.insert(tk.END, "Unexpected message from the server, DataLength could not be converted to Integer" + "\n")
                        progress_text.config(state=DISABLED)

                        return

            elif data == b'S REQ:description':
                description = desc_input.get('1.0', tk.END)

                if description == "":
                    progress_bar["value"] = 0
                    progress_percent.config(text="0%")

                    progress_text.config(state=NORMAL)
                    progress_text.insert(tk.END, "Description input not filled" + "\n")
                    progress_text.config(state=DISABLED)

                    data_channel.sendall(pynetstring.encode('E Description not filled'))

                    return

                data_channel.sendall(pynetstring.encode('C ' + description))

                progress_text.config(state=NORMAL)
                progress_text.insert(tk.END, "Description sent to the server" + "\n")
                progress_text.config(state=DISABLED)

                threading.Thread(target=progress_bar_add(5)).start()

                data = data_channel.recv(1024)
                data = pynetstring.decode(data)[0]
                data = data.decode('utf-8')

                if data[0:6] != "S ACK:":
                    progress_bar["value"] = 0
                    progress_percent.config(text="0%")

                    data_channel.sendall(pynetstring.encode('E Expected message not received (S ACK:<dataLength>)'))

                    progress_text.config(state=NORMAL)
                    progress_text.insert(tk.END, "Unexpected message from the server, ACK expected" + "\n")
                    progress_text.config(state=DISABLED)

                    return

                else:
                    data = data[6:]

                    try:
                        char_sum += int(data)

                    except ValueError:
                        progress_bar["value"] = 0
                        progress_percent.config(text="0%")

                        data_channel.sendall(pynetstring.encode('E DataLength not valid'))

                        progress_text.config(state=NORMAL)
                        progress_text.insert(tk.END, "Unexpected message from the server, DataLength could not be converted to Integer" + "\n")
                        progress_text.config(state=DISABLED)

                        return

            elif data == b'S REQ:isNSFW':
                isNSFW = nsfw_check.get()

                if isNSFW == 0:
                    data_channel.sendall(pynetstring.encode('C false'))

                else:
                    data_channel.sendall(pynetstring.encode('C true'))

                progress_text.config(state=NORMAL)
                progress_text.insert(tk.END, "NSFW status sent to the server" + "\n")
                progress_text.config(state=DISABLED)

                threading.Thread(target=progress_bar_add(5)).start()

                data = data_channel.recv(1024)
                data = pynetstring.decode(data)[0]
                data = data.decode('utf-8')

                if data[0:6] != "S ACK:":
                    progress_bar["value"] = 0
                    progress_percent.config(text="0%")

                    data_channel.sendall(pynetstring.encode('E Expected message not received (S ACK:<dataLength>)'))

                    progress_text.config(state=NORMAL)
                    progress_text.insert(tk.END, "Unexpected message from the server, ACK expected" + "\n")
                    progress_text.config(state=DISABLED)

                    return

                else:
                    data = data[6:]

                    try:
                        char_sum += int(data)

                    except ValueError:
                        progress_bar["value"] = 0
                        progress_percent.config(text="0%")

                        data_channel.sendall(pynetstring.encode('E DataLength not valid'))

                        progress_text.config(state=NORMAL)
                        progress_text.insert(tk.END, "Unexpected message from the server, DataLength could not be converted to Integer" + "\n")
                        progress_text.config(state=DISABLED)

                        return

            elif data == b'S REQ:password':
                password = pass_input.get()

                if password == "":
                    progress_bar["value"] = 0
                    progress_percent.config(text="0%")

                    progress_text.config(state=NORMAL)
                    progress_text.insert(tk.END, "Password input not filled" + "\n")
                    progress_text.config(state=DISABLED)

                    data_channel.sendall(pynetstring.encode('E Pescription not filled'))

                    return

                data_channel.sendall(pynetstring.encode('C ' + password))

                progress_text.config(state=NORMAL)
                progress_text.insert(tk.END, "Password sent to the server" + "\n")
                progress_text.config(state=DISABLED)

                threading.Thread(target=progress_bar_add(5)).start()

                data = data_channel.recv(1024)
                data = pynetstring.decode(data)[0]
                data = data.decode('utf-8')

                if data[0:6] != "S ACK:":
                    progress_bar["value"] = 0
                    progress_percent.config(text="0%")

                    data_channel.sendall(pynetstring.encode('E Expected message not received (S ACK:<dataLength>)'))

                    progress_text.config(state=NORMAL)
                    progress_text.insert(tk.END, "Unexpected message from the server, ACK expected" + "\n")
                    progress_text.config(state=DISABLED)

                    return

                else:
                    data = data[6:]

                    try:
                        char_sum += int(data)

                    except ValueError:
                        progress_bar["value"] = 0
                        progress_percent.config(text="0%")

                        data_channel.sendall(pynetstring.encode('E DataLength not valid'))

                        progress_text.config(state=NORMAL)
                        progress_text.insert(tk.END, "Unexpected message from the server, DataLength could not be converted to Integer" + "\n")
                        progress_text.config(state=DISABLED)

                        return

            else:
                data = data.decode('utf-8')

                if data[0:6] == "S END:":
                    DTOKEN = data[6:]

                    progress_text.config(state=NORMAL)
                    progress_text.insert(tk.END, "Server wants to finish transmission. DTOKEN received from the server" + "\n")
                    progress_text.config(state=DISABLED)

                    threading.Thread(target=progress_bar_add(5)).start()

                    if DTOKEN == TOKEN:
                        progress_bar["value"] = 0
                        progress_percent.config(text="0%")

                        progress_text.config(state=NORMAL)
                        progress_text.insert(tk.END, "DTOKEN is the same as TOKEN" + "\n")
                        progress_text.config(state=DISABLED)

                        data_channel.sendall(pynetstring.encode('E DTOKEN is the same as TOKEN'))

                        return

                    else:
                        break

                else:
                    progress_bar["value"] = 0
                    progress_percent.config(text="0%")

                    progress_text.config(state=NORMAL)
                    progress_text.insert(tk.END, "Unexpected message from the server" + "\n")
                    progress_text.config(state=DISABLED)

                    data_channel.sendall(pynetstring.encode('E Unexpected message from the server'))

                    return

    # third part - communication with the server on the main channel
    data = data_channel.recv(1024)
    data = pynetstring.decode(data)[0]
    data = data.decode('utf-8')

    if data[0:2] != "S ":
        progress_bar["value"] = 0
        progress_percent.config(text="0%")

        data_channel.sendall(pynetstring.encode('E Expected message not received (S <dataLength>)'))

        progress_text.config(state=NORMAL)
        progress_text.insert(tk.END, "Unexpected message from the server, S expected" + "\n")
        progress_text.config(state=DISABLED)

        return

    try:
        MSGLEN = int(data[2:])
    
    except ValueError:
        progress_bar["value"] = 0
        progress_percent.config(text="0%")

        data_channel.sendall(pynetstring.encode('E DataLength not valid'))

        progress_text.config(state=NORMAL)
        progress_text.insert(tk.END, "Unexpected message from the server, DataLength could not be converted to Integer" + "\n")
        progress_text.config(state=DISABLED)

        return

    if MSGLEN != char_sum:
        progress_bar["value"] = 0
        progress_percent.config(text="0%")

        data_channel.sendall(pynetstring.encode('E DataLength not valid'))

        progress_text.config(state=NORMAL)
        progress_text.insert(tk.END, "Unexpected message from the server, DataLength not equal to char sum" + "\n")
        progress_text.config(state=DISABLED)

        return

    # send dtoken to server
    s.sendall(pynetstring.encode('C ' + DTOKEN))

    progress_text.config(state=NORMAL)
    progress_text.insert(tk.END, "DTOKEN sent to the server" + "\n")
    progress_text.config(state=DISABLED)

    threading.Thread(target=progress_bar_add(5)).start()

    data = s.recv(1024)
    data = pynetstring.decode(data)[0]

    if data == b'S ACK:':
        progress_text.config(state=NORMAL)
        progress_text.insert(tk.END, "DTOKEN sent to the server, connection ready to end" + "\n")
        progress_text.config(state=DISABLED)

        threading.Thread(target=progress_bar_add(5)).start()
    
    else:
        progress_bar["value"] = 0
        progress_percent.config(text="0%")

        s.sendall(pynetstring.encode('E Expected message not received (S ACK)'))

        progress_text.config(state=NORMAL)
        progress_text.insert(tk.END, "Unexpected message from the server, (S ACK) message expected" + "\n")
        progress_text.config(state=DISABLED)

        return

    progress_text.config(state=NORMAL)
    progress_text.insert(tk.END, "Meme sent successfully" + "\n")
    progress_text.config(state=DISABLED)

    s.close()


# "adding progress" to progress bar
def progress_bar_add(progress):
    for i in range(progress):
        progress_bar["value"] += 1
        progress_bar.update()
        progress_percent.config(text=str(int(progress_bar["value"])) + "%")
        time.sleep(0.1)

    return


def load_meme():
    global image

    # load file from pc
    file = filedialog.askopenfilename(initialdir="/", title="Select file", filetypes=(("JPEG files", ("*.jpg", "*.jpeg")), ("PNG files", "*.png")))
    
    if file == "":
        progress_text.config(state=NORMAL)
        progress_text.insert(tk.END, "Import Cancelled" + "\n")
        progress_text.config(state=DISABLED)
        
        return 

    else:
        progress_text.config(state=NORMAL)
        progress_text.insert(tk.END, "Meme import successful" + "\n")
        progress_text.config(state=DISABLED)

        sel_file.config(text=os.path.split(file)[1])

    image = base64.b64encode(open(file, "rb").read()).decode("ascii")


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
upload_frame = tk.Frame(ws, background="#34393E", width=1144, height=300)
upload_frame.grid(row=5, column=0, columnspan=3, sticky="n", pady=10)
upload_frame.grid_propagate(0)

# upload meme from PC button
upload_button = tk.Button(upload_frame, text="Upload MEME from PC", width=20, background="#FDCB52", font=("Helvetica", 12, "bold"), fg="#34393E", activebackground="#34393E", activeforeground="#FDCB52", command=load_meme)
upload_button.grid(row=0, column=0, sticky='w')

# post meme button
post_button = tk.Button(upload_frame, text="Post MEME", width=10, background="#FDCB52", font=("Helvetica", 12, "bold"), fg="#34393E", activebackground="#34393E", activeforeground="#FDCB52", command=meme_post)
post_button.grid(row=0, column=11, sticky='e')

sel_file = tk.Label(upload_frame, text="*No file selected", background="#34393E", font=("Helvetica", 12, "bold"), fg="#FDCB52")
sel_file.grid(row=0, column=1, sticky='w', padx=3)

# progress bar
progress_text = tk.Text(upload_frame, width=163, height=8, font=("Helvetica", 10), fg="#34393E", background="#BFBFBF", state="disabled")
progress_text.grid(row=1, rowspan=3, column=0, columnspan=12, sticky='wn', pady=20)

progress_bar = ttk.Progressbar(upload_frame, orient="horizontal", length=1144, mode="determinate")
progress_bar.grid(row=4, column=0, columnspan=12, sticky='wn')

progress_percent = tk.Label(upload_frame, text=str(int(progress_bar["value"])) + "%", background="#34393E", font=("Helvetica", 12, "bold"), fg="#FDCB52")
progress_percent.grid(row=5, column=0, sticky='w', pady=5)


# RUN THE APP MAINLOOP
ws.mainloop()
