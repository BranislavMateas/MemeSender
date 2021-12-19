# dependencies
import tkinter as tk
from tkinter import filedialog
from tkinter import scrolledtext
from tkinter import ttk
import socket
import pynetstring
import base64
import threading
from tkinter import *
import os

# WINDOW AND FRAMES SETUP
# window setup
ws = tk.Tk()
ws.title("Meme sender")
ws.geometry("1200x580")
ws.resizable(False, False)
ws.configure(background='#34393E')

# button state variable
status = IntVar()

# netstrings decoder initialization
decoder = pynetstring.Decoder()


# MAIN FUNCTION
def meme_post():
    # setting up the fields
    progress_text.config(state=NORMAL)
    progress_text.delete('1.0', END)
    progress_text.config(state=DISABLED)

    clear_progress()

    # checking if meme was imported
    if sel_file.cget("text") == "*No file selected":
        update_textarea("No file selected")
        threading.Thread(target=load_meme())

    ip = ip_input.get()
    port = port_input.get()

    # checking if ip and port fields are empty
    if ip == "" or port == "":
        update_textarea("IP or Port field is empty")
        return

    try:
        # connecting to server
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, int(port)))

    except ConnectionRefusedError:
        clear_progress()
        update_textarea("Connection refused by the server")
        return

    except TimeoutError:
        clear_progress()
        update_textarea("Connection timed out")
        return

    except (socket.gaierror, ValueError):
        clear_progress()
        update_textarea("Invalid IP or Port")
        return

    except ConnectionAbortedError:
        clear_progress()
        update_textarea("Connection aborted")
        return

    # sending server initializating message
    update_textarea("Server reached, initializating connection")

    s.sendall(pynetstring.encode('C MTP V:1.0'))
    data = s.recv(1024)

    # adding progress
    threading.Thread(target=progress_bar_add(5)).start()

    # checking if correct message was received
    if pynetstring.decode(data) == [b'S MTP V:1.0']:
        update_textarea("Connection initialized: " + ip + ":" + port)
        threading.Thread(target=progress_bar_add(5)).start()
    else:
        s.sendall(pynetstring.encode(
            'E Expected message not received (S MTP V:1.0)'))
        threading.Thread(target=clear_progress()).start()
        threading.Thread(target=update_textarea(
            "Connection failed: " + pynetstring.decode(data)[0])).start()
        return

    # checking if nick field is empty
    nick = nick_input.get()

    if nick == "":
        # sending server error message
        s.sendall(pynetstring.encode('E Nick not filled'))
        threading.Thread(target=clear_progress()).start()
        threading.Thread(target=update_textarea("Nick not filled")).start()
        return

    # sending nick to server
    s.sendall(pynetstring.encode('C ' + nick))

    # receiving server security token
    data = s.recv(1024)
    TOKEN = pynetstring.decode(data)[0]

    # checking token validity
    TOKEN = TOKEN.decode('utf-8')

    if TOKEN[0:2] != "S " or len(TOKEN) < 3:
        s.sendall(pynetstring.encode('E Received token is not valid'))
        threading.Thread(target=clear_progress()).start()
        threading.Thread(target=update_textarea(
            "Invalid token received")).start()
        return

    TOKEN = TOKEN[2:]

    threading.Thread(target=progress_bar_add(5)).start()

    # receiving port number from the server
    data = s.recv(1024)
    PORT = pynetstring.decode(data)[0]

    # checking port validity
    PORT = PORT.decode('utf-8')

    if PORT[0:2] != "S " or len(PORT) < 3:
        s.sendall(pynetstring.encode('E Received message was not expected'))
        threading.Thread(target=clear_progress()).start()
        threading.Thread(target=update_textarea(
            "Unexpected message from the server")).start()
        return
    else:
        try:
            PORT = int(PORT[2:])

            update_textarea("Port received: " + str(PORT))
            threading.Thread(target=progress_bar_add(5)).start()

        except ValueError:
            s.sendall(pynetstring.encode(
                'E Computer expected port number or received port is not valid'
                ))
            threading.Thread(target=clear_progress()).start()
            threading.Thread(target=update_textarea(
                "Invalid port message received")).start()
            return

    update_textarea("Opening DataChannel connection")

    # establishing connection with the data channel
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as data_channel:
        try:
            data_channel.connect((ip, PORT))

            threading.Thread(target=update_textarea(
                "DataChannel connection established")).start()
            threading.Thread(target=progress_bar_add(5)).start()

        except Exception:
            data_channel.sendall(pynetstring.encode(
                'E DataChannel connection failed'))
            threading.Thread(target=clear_progress()).start()
            threading.Thread(target=update_textarea(
                "Server did not open the Data Channel")).start()
            return

        # sending nick to the server in order to
        # receive security token from the server
        data_channel.sendall(pynetstring.encode('C ' + nick))

        # receiving server security token
        data = data_channel.recv(1024)
        SEC_TOKEN = pynetstring.decode(data)[0]
        SEC_TOKEN = SEC_TOKEN.decode('utf-8')

        if SEC_TOKEN[0:2] != "S " or len(SEC_TOKEN) < 3:
            s.sendall(pynetstring.encode(
                'E Expected message not received (S <token>)'))
            threading.Thread(target=clear_progress()).start()
            threading.Thread(target=update_textarea(
                "Security token expected")).start()
            return
        else:
            SEC_TOKEN = SEC_TOKEN[2:]

            update_textarea("Security token received: ")
            threading.Thread(target=progress_bar_add(5)).start()

        if SEC_TOKEN != TOKEN:
            s.sendall(pynetstring.encode('E Security token mismatch'))
            threading.Thread(target=clear_progress()).start()
            threading.Thread(target=update_textarea(
                "Security token mismatch")).start()
            return
        else:
            progress_text.config(state=NORMAL)
            progress_text.insert(tk.END, "Tokens verified" + "\n")
            progress_text.config(state=DISABLED)

            threading.Thread(target=progress_bar_add(5)).start()

        # DATA TRANSFER
        char_sum = 0
        password = pass_input.get()
        description = desc_input.get("1.0", tk.END)
        nsfw = status.get()

        for i in range(9):
            data = data_channel.recv(1024)
            data = pynetstring.decode(data)[0]

            # type of data
            if data == b'S REQ:meme':
                data_channel.sendall(pynetstring.encode('C ' + image))
                threading.Thread(target=update_textarea(
                    "Meme sent to the server")).start()
                threading.Thread(target=progress_bar_add(10)).start()

            elif data == b'S REQ:password':
                if password == "":
                    clear_progress()
                    update_textarea("Password is not filled")
                    return

                data_channel.sendall(pynetstring.encode('C ' + password))
                threading.Thread(target=update_textarea(
                    "Password sent to the server")).start()
                threading.Thread(target=progress_bar_add(10)).start()

            elif data == b'S REQ:description':
                if description == "":
                    clear_progress()
                    update_textarea("Description is not filled")
                    return

                data_channel.sendall(pynetstring.encode('C ' + description))
                threading.Thread(target=update_textarea(
                    "Description sent to the server")).start()
                threading.Thread(target=progress_bar_add(10)).start()

            elif data == b'S REQ:isNSFW':
                if nsfw == 0:
                    threading.Thread(target=data_channel.sendall(
                        pynetstring.encode('C false'))).start()
                else:
                    threading.Thread(target=data_channel.sendall(
                        pynetstring.encode('C true'))).start()

                threading.Thread(target=update_textarea(
                    "NSFW status sent to the server")).start()
                threading.Thread(target=progress_bar_add(10)).start()

            # special responses
            elif b'S END:' in data:
                data = data.decode('utf-8')
                DTOKEN = data[6:]
                break

            elif b'S ACK:' in data:
                if not datasum(char_sum, data[6:]):
                    data_channel.sendall(pynetstring.encode(
                        'E DataLength not valid'))
                    return
                else:
                    char_sum = datasum(char_sum, data[6:])

            else:
                threading.Thread(target=clear_progress()).start()
                threading.Thread(target=data_channel.sendall(
                    pynetstring.encode(
                        'E Expected message not received (S ACK:<dataLength>)'
                        ))).start()
                threading.Thread(target=update_textarea(
                    "Unexpected message from the server")).start()
                return

    # third part - communication with the server on the main channel
    data = s.recv(1024)
    data = pynetstring.decode(data)[0]
    data = data.decode('utf-8')

    if data[0:2] != "S ":
        data_channel.sendall(pynetstring.encode(
            'E Expected message not received (S <dataLength>)'))
        threading.Thread(target=clear_progress()).start()
        update_textarea(
            "Unexpected message from the server, (S <msglen>) expected"
            )
        return

    try:
        MSGLEN = int(data[2:])

    except ValueError:
        data_channel.sendall(
            pynetstring.encode('E DataLength not valid'))
        threading.Thread(target=clear_progress()).start()
        threading.Thread(target=update_textarea(
            "Unexpected message from the server," +
            " DataLength could not be converted to Integer")).start()
        return

    if MSGLEN != char_sum:
        data_channel.sendall(pynetstring.encode('E DataLength not valid'))
        threading.Thread(target=clear_progress()).start()
        threading.Thread(target=update_textarea(
            "Unexpected message from the server, DataLength not valid"
            )).start()
        return

    # send dtoken to server
    s.sendall(pynetstring.encode('C ' + DTOKEN))
    threading.Thread(target=update_textarea(
        "DTOKEN sent to the server")).start()
    threading.Thread(target=progress_bar_add(5)).start()

    # receiving server final response
    data = s.recv(1024)
    data = pynetstring.decode(data)[0]

    if data == b'S ACK':
        update_textarea("Connection ready to end")
        threading.Thread(target=clear_progress()).start()
        threading.Thread(target=progress_bar_add(5)).start()
    else:
        s.sendall(pynetstring.encode(
            'E Expected message not received (S ACK)'))
        threading.Thread(target=clear_progress()).start()
        threading.Thread(target=update_textarea(
            "Unexpected message from the server, (S ACK) message expected"
            )).start()
        return

    update_textarea("Meme sent successfully")

    # complete the progressbar
    threading.Thread(target=progress_bar_add(100-int(
        str(progress_percent.cget("text")).replace("%", "")
        ))).start()

    s.close()


# "adding progress" to progress bar
def progress_bar_add(progress):
    for i in range(progress):
        progress_bar["value"] += 1
        progress_bar.update()
        progress_percent.config(text=str(int(progress_bar["value"])) + "%")
    return


def load_meme():
    global image

    # load file from pc
    file = filedialog.askopenfilename(
        initialdir="/", title="Select file", filetypes=(
            ("JPEG files", ("*.jpg", "*.jpeg")), ("PNG files", "*.png")
            ))

    if file == "":
        update_textarea("Import Cancelled")
        return
    else:
        update_textarea("Meme import successful")
        sel_file.config(text=os.path.split(file)[1])

    image = base64.b64encode(open(file, "rb").read()).decode("ascii")
    return


def update_textarea(content):
    progress_text.config(state=NORMAL)
    progress_text.insert(tk.END, content + "\n")
    progress_text.config(state=DISABLED)
    ws.update_idletasks()

    # scroll textarea to the latest message
    progress_text.see(tk.END)
    return


def datasum(char_sum, to_sum):
    try:
        char_sum += int(to_sum)
        return char_sum

    except ValueError:
        clear_progress()
        threading.Thread(target=update_textarea(
            "Unexpected message from the server, " +
            "DataLength could not be converted to Integer"
            )).start()
        return False


def clear_progress():
    progress_bar["value"] = 0
    progress_percent.config(text="0%")
    ws.update_idletasks()
    return


# CREDITENTIALS FRAME
# left frame with creditentials input
left_cred = tk.Frame(ws, background="#34393E", width=550, height=60)
left_cred.grid(row=0, column=0, rowspan=2, sticky="nw", padx=20, pady=20)
left_cred.grid_propagate(0)

# ip part
ip_label = tk.Label(left_cred, text="IP address:", background="#34393E", font=(
    "Helvetica", 12, "bold"), fg="#FDCB52")
ip_label.grid(row=0, column=0, sticky='nsew', padx=3)

ip_input = tk.Entry(left_cred, width=50, font=("Helvetica", 12))
ip_input.grid(row=0, column=1)

# nickaname part
nick_label = tk.Label(
    left_cred, text="Nickname:", background="#34393E",
    font=("Helvetica", 12, "bold"), fg="#FDCB52")
nick_label.grid(row=1, column=0, sticky='w', pady=10, padx=3)

nick_input = tk.Entry(left_cred, width=50, font=("Helvetica", 12))
nick_input.grid(row=1, column=1)


# right frame with creditentials input
right_cred = tk.Frame(ws, background="#34393E", width=550, height=60)
right_cred.grid(row=0, column=1, rowspan=2, sticky="nw", padx=20, pady=20)
right_cred.grid_propagate(0)

# port part
port_label = tk.Label(
    right_cred, text="Port Num.:", background="#34393E",
    font=("Helvetica", 12, "bold"), fg="#FDCB52")
port_label.grid(row=0, column=0, sticky='w', padx=3)

port_input = tk.Entry(right_cred, width=50, font=("Helvetica", 12))
port_input.grid(row=0, column=1)

# nickaname part
pass_label = tk.Label(
    right_cred, text="Password:", background="#34393E",
    font=("Helvetica", 12, "bold"), fg="#FDCB52")
pass_label.grid(row=1, column=0, sticky='w', pady=10, padx=3)

pass_input = tk.Entry(right_cred, width=50, font=("Helvetica", 12))
pass_input.grid(row=1, column=1)


# MEME DETATAILS FRAME
meme_frame = tk.Frame(ws, background="#34393E", width=1150, height=185)
meme_frame.grid(row=3, column=0, columnspan=2, sticky="n", padx=22)
meme_frame.grid_propagate(0)

# description part
desc_label = tk.Label(
    meme_frame, text="Description:", background="#34393E",
    font=("Helvetica", 12, "bold"), fg="#FDCB52")
desc_label.grid(row=0, column=0, sticky='w')

desc_input = tk.scrolledtext.ScrolledText(
    meme_frame, width=102, height=5, font=("Helvetica", 14))
desc_input.grid(row=1, column=0, sticky='w', padx=3, pady=2)

nsfw_check = tk.Checkbutton(
    meme_frame, text="is NSFW (Not safe for work)", variable=status,
    background="#34393E", font=("Helvetica", 12, "bold"),
    highlightbackground="#34393E", fg="#FDCB52", activebackground="#34393E",
    activeforeground="#FDCB52", bd=0, disabledforeground="#FDCB52"
    )
nsfw_check.grid(row=2, column=0, sticky='w', pady=2)


# BUTTONS AND PROGRESS BAR FRAME
upload_frame = tk.Frame(ws, background="#34393E", width=1144, height=300)
upload_frame.grid(row=5, column=0, columnspan=3, sticky="n", pady=10)
upload_frame.grid_propagate(0)

# upload meme from PC button
upload_button = tk.Button(
    upload_frame, text="Upload MEME from PC", width=20,
    background="#FDCB52", font=("Helvetica", 12, "bold"), fg="#34393E",
    activebackground="#34393E", activeforeground="#FDCB52", command=load_meme
    )
upload_button.grid(row=0, column=0, sticky='w')

# post meme button
post_button = tk.Button(
    upload_frame, text="Post MEME", width=10, background="#FDCB52",
    font=("Helvetica", 12, "bold"), fg="#34393E", activebackground="#34393E",
    activeforeground="#FDCB52", command=meme_post
    )
post_button.grid(row=0, column=11, sticky='e')

sel_file = tk.Label(
    upload_frame, text="*No file selected", background="#34393E",
    font=("Helvetica", 12, "bold"), fg="#FDCB52"
    )
sel_file.grid(row=0, column=1, sticky='w', padx=3)

# progress bar
progress_text = tk.Text(
    upload_frame, width=163, height=8, font=("Helvetica", 10), fg="#34393E",
    background="#BFBFBF", state="disabled"
    )
progress_text.grid(
    row=1, rowspan=3, column=0, columnspan=12, sticky='wn', pady=20)

progress_bar = ttk.Progressbar(
    upload_frame, orient="horizontal", length=1144, mode="determinate")
progress_bar.grid(row=4, column=0, columnspan=12, sticky='wn')

progress_percent = tk.Label(
    upload_frame, text=str(int(progress_bar["value"])) + "%",
    background="#34393E", font=("Helvetica", 12, "bold"), fg="#FDCB52"
    )
progress_percent.grid(row=5, column=0, sticky='w', pady=5)


# RUN THE APP MAINLOOP
ws.mainloop()
