import calendar
import datetime
import json
import os
import re
import sys
import time
import tkinter
from base64 import b64decode, b64encode
from tkinter import CENTER, END

import customtkinter
import pymssql
import requests
from dotenv import load_dotenv
from PIL import Image

customtkinter.set_appearance_mode("dark")

load_dotenv()


def resource_path(relative_path):
    """Get absolute path to resource, works for dev and for PyInstaller"""
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = getattr(sys, "_MEIPASS", os.path.abspath("."))
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)


granite_icon = resource_path("granite.ico")
qt_logo = resource_path("quicktracker.png")


def center_win(root):
    w = root.winfo_reqwidth()
    h = root.winfo_reqheight()
    ws = root.winfo_screenwidth()
    hs = root.winfo_screenheight()
    x = (ws / 2) - (w / 2)
    y = (hs / 2) - (h / 2)
    root.geometry("+%d+%d" % (x, y))


def splash():
    main = customtkinter.CTk()
    main.title("  Granite QuickTracker")
    main.wm_iconbitmap(granite_icon)
    main.attributes("-alpha", 0.95)
    center_win(main)
    logo = customtkinter.CTkImage(dark_image=Image.open(qt_logo), size=(500, 200))
    customtkinter.CTkLabel(main, text="", image=logo).pack()
    customtkinter.CTkLabel(
        master=main, text="Please wait while the application loads..."
    ).pack()
    main.after(4000, lambda: main.destroy())
    main.mainloop()


splash()


def exitProg():
    sys.exit()


def obfuscate(plainText):
    plainBytes = plainText.encode("ascii")
    encodedBytes = b64encode(plainBytes)
    encodedText = encodedBytes.decode("ascii")
    return encodedText


def deobfuscate(obfuscatedText):
    obfuscatedBytes = obfuscatedText.encode("ascii")
    decodedBytes = b64decode(obfuscatedBytes)
    decodedText = decodedBytes.decode("ascii")
    return decodedText


def encrypt(pw):
    encrypted = obfuscate(obfuscate(obfuscate(obfuscate(obfuscate(pw)))))
    return encrypted


def decrypt(pw):
    decrypted = deobfuscate(deobfuscate(deobfuscate(deobfuscate(deobfuscate(pw)))))
    return decrypted


def getCreds():
    def printValue(event=None):  # Combined both functions into one
        global user_name, password
        user_name = un.get()
        password = pwd.get()
        main.destroy()

    main = customtkinter.CTk()
    main_frame = customtkinter.CTkFrame(master=main, width=1000)
    main.title("  Granite QuickTracker")
    main.wm_iconbitmap(granite_icon)
    main.attributes("-alpha", 0.95)
    center_win(main)
    un = customtkinter.CTkEntry(main_frame, placeholder_text="Username")
    un.pack(padx=70, pady=10)
    pwd = customtkinter.CTkEntry(main_frame, placeholder_text="Password", show="*")
    pwd.pack(padx=70, pady=(0, 10))
    main.bind("<Return>", printValue)
    customtkinter.CTkButton(main_frame, text="Submit", command=printValue).pack(
        pady=(0, 10)
    )
    main.protocol("WM_DELETE_WINDOW", exitProg)
    main_frame.pack(padx=10, pady=(10))
    main.mainloop()


def login():
    global connection, cursor, user_name, password

    def try_connect():
        try:
            return pymssql.connect(
                server="gp2018",
                user=f"GRT0\\{user_name}",
                password=password,
                database="SBM01",
            )
        except Exception as e:
            print(f"Connection error: {e}")
            return None

    while True:
        try:
            if os.path.exists("credentials.txt"):
                with open("credentials.txt", "r") as creds:
                    lines = creds.readlines()
                    if len(lines) >= 2:
                        user_name = decrypt(lines[0].strip())
                        password = decrypt(lines[1].strip())
                    else:
                        raise ValueError("Invalid credentials file format")
            else:
                getCreds()

            connection = try_connect()
            if connection:
                cursor = connection.cursor()
                # Save valid credentials
                if not os.path.exists("credentials.txt"):
                    with open("credentials.txt", "w") as fh:
                        fh.write(f"{encrypt(user_name)}\n")
                        fh.write(f"{encrypt(password)}")
                break
            else:
                # Invalid credentials, remove file and try again
                if os.path.exists("credentials.txt"):
                    os.remove("credentials.txt")
                getCreds()

        except Exception as e:
            print(f"Login error: {e}")
            if os.path.exists("credentials.txt"):
                os.remove("credentials.txt")
            getCreds()
            # Update global variables with new credentials
            user_name = None
            password = None


def recognize_delivery_service(tracking):
    service = None

    usps_pattern = [
        "^(94|93|92|94|95)[0-9]{20}$",
        "^(94|93|92|94|95)[0-9]{22}$",
        "^(70|14|23|03)[0-9]{14}$",
        "^(M0|82)[0-9]{8}$",
        "^([A-Z]{2})[0-9]{9}([A-Z]{2})$",
    ]

    ups_pattern = [
        "^(1Z)[0-9A-Z]{16}$",
        "^(T)+[0-9A-Z]{10}$",
        "^[0-9]{9}$",
        "^[0-9]{26}$",
    ]

    fedex_pattern = ["^[0-9]{20}$", "^[0-9]{15}$", "^[0-9]{12}$", "^[0-9]{22}$"]

    usps = "(" + ")|(".join(usps_pattern) + ")"
    fedex = "(" + ")|(".join(fedex_pattern) + ")"
    ups = "(" + ")|(".join(ups_pattern) + ")"

    if re.match(usps, tracking) is not None:
        service = "USPS"
    elif re.match(ups, tracking) is not None:
        service = "UPS"
    elif re.match(fedex, tracking) is not None:
        service = "FedEx"

    return service


def main():
    global tkt, tkt_list, text_response
    text_response = []

    def printValue(event):
        global tkt, tkt_list
        tkt = ticket.get("1.0", "end-1c")
        tkt_list = tkt.replace(",", " ").replace("\n", " ").split()
        button.configure(text="Please wait...")
        main.after(3, lambda: track_tickets())
        main.after(3, lambda: main.destroy())

    def printValue2():
        global tkt, tkt_list
        tkt = ticket.get("1.0", "end-1c")
        tkt_list = tkt.replace(",", " ").replace("\n", " ").split()
        button.configure(text="Please wait...")
        main.after(3, lambda: track_tickets())
        main.after(3, lambda: main.destroy())

    main = customtkinter.CTk()
    main_frame = customtkinter.CTkFrame(master=main)
    main.title("  Granite QuickTracker")
    main.wm_iconbitmap(granite_icon)
    main.attributes("-alpha", 0.95)
    center_win(main)
    customtkinter.CTkLabel(
        master=main_frame, text="Please enter the ticket number(s):"
    ).pack(pady=(20, 0))
    ticket = customtkinter.CTkTextbox(master=main_frame, width=250, height=70)
    ticket.pack(padx=100, pady=10)
    main.bind("<Return>", printValue)
    button = customtkinter.CTkButton(main_frame, text="Submit", command=printValue2)
    button.pack(padx=10, pady=(0, 10))
    main.protocol("WM_DELETE_WINDOW", exitProg)
    main_frame.pack(padx=10, pady=10)
    main.mainloop()


def main2():
    main2 = customtkinter.CTk()
    main2.title("  Granite QuickTracker")
    main2.wm_iconbitmap(granite_icon)
    main2.attributes("-alpha", 0.95)
    main2_frame = customtkinter.CTkFrame(master=main2)
    greeting = customtkinter.CTkLabel(
        master=main2_frame, text="Loading results...", width=200, height=100
    )
    greeting.pack(anchor="center")
    main2_frame.pack(padx=10, pady=10)
    main2.after(1, lambda: track_tickets())
    main2.after(3, lambda: main2.destroy())
    main2.mainloop()


def main_alt():
    global tkt, tkt_list, text_response, startTime
    text_response = []
    startTime = time.time()

    def add_tracking():
        global text_response
        for i in text_response:
            text.insert(END, str(i) + "\n")
        text_response = []

    def actual_print():
        global tkt, tkt_list, startTime, ups_access_token, fedex_access_token, text_response, cleared
        tkt = ticket.get("1.0", "end-1c")
        tkt_list = tkt.replace(",", " ").replace("\n", " ").split()
        if cleared:
            main.after(3, lambda: text.delete("0.0", "end"))
        main.after(3, lambda: text.configure(text_color="white"))
        main.after(3, lambda: add_tracking())
        main.after(2, lambda: button.configure(text="Please wait..."))
        cleared = False
        if time.time() - startTime > 3000:
            ups_access_token = json.loads(
                session.post(
                    "https://wwwcie.ups.com/security/v1/oauth/token",
                    headers=ups_headers,
                    data=ups_data,
                ).content
            )["access_token"]

            fedex_access_token = json.loads(
                session.post(
                    "https://apis.fedex.com/oauth/token",
                    data=fedex_payload,
                    headers=fedex_headers,
                ).text
            )["access_token"]
            startTime = time.time()
        main.after(3, lambda: track_tickets())
        main.after(3, lambda: add_tracking())
        main.after(4, lambda: button.configure(text="Submit"))

    def printValue(event):
        global tkt, tkt_list
        actual_print()

    def printValue2():
        global tkt, tkt_list
        actual_print()

    def clear():
        global tkt_list, text_response
        tkt_list = []
        text_response = []
        main.after(3, lambda: text.delete("0.0", "end"))
        main.after(3, lambda: ticket.delete("0.0", "end"))
        main.after(3, lambda: text.insert(END, insert_initial()))

    def endProg():
        sys.exit()

    def insert_initial():
        global cleared
        cleared = True
        main.after(3, lambda: text.configure(text_color="gray"))
        joke = requests.get(
            "https://icanhazdadjoke.com", headers={"Accept": "application/json"}
        ).json()["joke"]
        initial_text = f"""Enter the ticket numbers above separated by any combination of commas, spaces, or line-breaks.





Random dad joke:

{joke.strip()}





Created by Mikey Marcotte"""
        text.tag_config("tag-center", justify=CENTER)
        text.insert(END, initial_text, "tag-center")

    main = customtkinter.CTk()
    main_frame = customtkinter.CTkFrame(master=main)
    main.title("  Granite QuickTracker")
    main.wm_iconbitmap(granite_icon)
    main.attributes("-alpha", 0.95)
    center_win(main)
    customtkinter.CTkLabel(
        master=main_frame, text="Please enter the ticket number(s):"
    ).pack(pady=(20, 0), padx=108)
    ticket = customtkinter.CTkTextbox(master=main_frame, width=270, height=70)
    ticket.pack(padx=10, pady=10)
    main.bind("<Return>", printValue)
    button = customtkinter.CTkButton(
        master=main_frame, text="Submit", command=printValue2
    )
    button.pack(padx=10, pady=(0, 10))
    main.protocol("WM_DELETE_WINDOW", exitProg)
    main_frame.pack(padx=10, pady=10)
    win_frame = customtkinter.CTkFrame(main)
    text = customtkinter.CTkTextbox(
        master=win_frame, wrap=tkinter.WORD, width=400, height=300, text_color="gray"
    )
    text.pack(padx=10, pady=10)
    insert_initial()
    customtkinter.CTkButton(
        master=win_frame, text="Clear", width=100, command=clear
    ).pack(side="left", anchor="ne", expand=True, padx=5, pady=(0, 10))
    customtkinter.CTkButton(
        master=win_frame, text="Exit", width=100, command=endProg
    ).pack(side="right", anchor="nw", expand=True, padx=5, pady=(0, 10))
    win_frame.pack(padx=10, pady=(0, 10))
    main.mainloop()


def popUp():
    global text_response, startOver, write1

    def restart():
        global startOver
        startOver = True
        win.destroy()

    def endProg():
        sys.exit()

    win = customtkinter.CTk()
    win.title("  Granite QuickTracker")
    win.wm_iconbitmap(granite_icon)
    win.attributes("-alpha", 0.95)
    center_win(win)
    win_frame = customtkinter.CTkFrame(win)
    text = customtkinter.CTkTextbox(win_frame, wrap=tkinter.WORD, width=390, height=400)
    for i in text_response:
        text.insert(END, str(i) + "\n")
    text.pack(padx=10, pady=10)
    customtkinter.CTkButton(
        win_frame, text="Start Over", width=100, command=restart
    ).pack(side="left", anchor="ne", expand=True, padx=5, pady=(0, 10))
    customtkinter.CTkButton(win_frame, text="Exit", width=100, command=endProg).pack(
        side="right", anchor="nw", expand=True, padx=5, pady=(0, 10)
    )
    win.protocol("WM_DELETE_WINDOW", exitProg)
    win_frame.pack(padx=10, pady=10)
    win.mainloop()


tkt_list = []
tkt_num = 0
session = requests.session()

# get ups access_token
ups_headers = {
    "accept": "application/json",
    "Authorization": f"Basic {os.getenv('UPS_AUTH')}",
    "Content-Type": "application/x-www-form-urlencoded",
}

ups_data = {
    "grant_type": "client_credentials",
}

ups_access_token = json.loads(
    session.post(
        "https://wwwcie.ups.com/security/v1/oauth/token",
        headers=ups_headers,
        data=ups_data,
    ).content
)["access_token"]

# get fedex access_token
fedex_payload = {
    "grant_type": "client_credentials",
    "client_id": os.getenv("FEDEX_CLIENT_ID"),
    "client_secret": os.getenv("FEDEX_CLIENT_SECRET"),
}
fedex_headers = {
    "Content-Type": "application/x-www-form-urlencoded",
}

fedex_access_token = json.loads(
    session.post(
        "https://apis.fedex.com/oauth/token", data=fedex_payload, headers=fedex_headers
    ).text
)["access_token"]
startTime = time.time()
text_response = []


def track_tickets():
    global tkt, tkt_list, fedex_access_token, ups_access_token, startTime

    for tkt in tkt_list:
        tkt = tkt.strip()
        cursor.execute(
            f"""declare @ticket as varchar(100) = '{tkt}'
select distinct coalesce(sop10107.SOPNUMBE, sop30200.SOPNUMBE, sop10100.SOPNUMBE) as 
        SOPNUMBE, Tracking_Number, coalesce(sop10100.BACHNUMB, sop30200.BACHNUMB) as BACHNUMB from SOP10107 full join 
        sop10100 on sop10100.SOPNUMBE = sop10107.SOPNUMBE full join sop30200 on SOP30200.SOPNUMBE = sop10107.SOPNUMBE 
        where ((sop10100.SOPNUMBE = @ticket or sop10100.SOPNUMBE = 'CW' + @ticket + '-1')
    or (sop30200.SOPNUMBE = @ticket or sop30200.SOPNUMBE = 'CW' + @ticket + '-1')
    or (sop10107.SOPNUMBE = @ticket or sop10107.SOPNUMBE = 'CW' + @ticket + '-1'))"""
        )
        try:
            sql_row = cursor.fetchone()
            inquiry_number = sql_row[1].strip().upper()
        except:
            inquiry_number = False
        if inquiry_number:
            shipper = recognize_delivery_service(inquiry_number)
            if shipper == "UPS":
                headers = {
                    "accept": "*/*",
                    "transId": tkt,
                    "transactionSrc": "testing",
                    "Authorization": f"Bearer {ups_access_token}",
                    "Content-Type": "application/json",
                }

                params = {
                    "locale": "en_US",
                    "returnSignature": "false",
                }

                tracking_info = session.get(
                    f"https://onlinetools.ups.com/api/track/v1/details/{inquiry_number}",
                    params=params,
                    headers=headers,
                ).content
                try:
                    status = json.loads(tracking_info)["trackResponse"]["shipment"][0][
                        "package"
                    ][0]["activity"][0]["status"]["description"].strip()
                    try:
                        del_date = json.loads(tracking_info)["trackResponse"][
                            "shipment"
                        ][0]["package"][0]["deliveryDate"][0]["date"]
                        del_date = datetime.datetime.strptime(del_date, "%Y%m%d")
                        del_date = f"{str(calendar.month_name[del_date.month])} {str(del_date.day)}, {str(del_date.year)}".strip()
                        del_time = json.loads(tracking_info)["trackResponse"][
                            "shipment"
                        ][0]["package"][0]["deliveryTime"]["type"].strip()
                        if del_time == "CMT":
                            del_time = "AM"
                        datestr = f"{del_date} by {del_time}"
                    except:
                        datestr = (
                            "The delivery date will be provided as soon as possible."
                        )
                except:
                    datestr = False
                    status = (
                        "We could not locate the shipment details for this tracking number. Details are only "
                        "available for shipments made within the last 120 days. Please check your information. "
                    )
            elif shipper == "FedEx":
                payload = json.dumps(
                    {
                        "trackingInfo": [
                            {"trackingNumberInfo": {"trackingNumber": inquiry_number}}
                        ],
                        "includeDetailedScans": False,
                    }
                )
                headers = {
                    "Content-Type": "application/json",
                    "x-customer-transaction-id": tkt,
                    "X-locale": "en_US",
                    "Authorization": f"Bearer {fedex_access_token}",
                }

                response = requests.post(
                    "https://apis.fedex.com/track/v1/trackingnumbers",
                    data=payload,
                    headers=headers,
                )

                status = json.loads(response.content)["output"]["completeTrackResults"][
                    0
                ]["trackResults"][0]["latestStatusDetail"]["statusByLocale"]
                del_date = json.loads(response.content)["output"][
                    "completeTrackResults"
                ][0]["trackResults"][0]["dateAndTimes"][0]["dateTime"]
                del_date = del_date.replace("T", " ").split()
                del_date, del_time = del_date
                del_date = del_date.replace("-", "")
                del_date = datetime.datetime.strptime(del_date, "%Y%m%d")
                del_date = f"{str(calendar.month_name[del_date.month])} {str(del_date.day)}, {str(del_date.year)}".strip()
                del_time = del_time.replace("-", " ").split()[0]
                del_time = del_time.replace(":", " ").split()[0:2]
                delimiter = ":"
                del_time = delimiter.join(del_time)
                if del_time == "00:00":
                    del_time = "EOD"
                datestr = f"{del_date} by {del_time}"
            else:
                status = ""
                datestr = ""
        else:
            datestr = False
            try:
                status = sql_row[2].strip()
                if status == "RDY TO INVOICE":
                    status = (
                        status
                        + " - No tracking available. This may be a partial shipment. Tracking may be "
                        "associated with another ticket number. "
                    )
            except:
                status = "Ticket not found"
        text_response.append(f"Ticket: {tkt}")
        del tkt
        if inquiry_number:
            text_response.append(f"Tracking number: {inquiry_number}")
            del inquiry_number
        if status:
            text_response.append(f"Status: {status}")
        if "delivered" in status.lower():
            text_response.append(f"Delivery date: {del_date}")
            del status
            del del_date
        elif "returned" in status.lower():
            pass
        else:
            if datestr:
                text_response.append(f"Estimated delivery: {datestr}")
                del datestr
            else:
                pass
        text_response.append("")

    if time.time() - startTime > 3000:
        ups_headers = {
            "accept": "application/json",
            "Authorization": f"Basic {os.getenv('UPS_AUTH')}",
            "Content-Type": "application/x-www-form-urlencoded",
        }

        ups_data = {
            "grant_type": "client_credentials",
        }

        ups_access_token = json.loads(
            session.post(
                "https://wwwcie.ups.com/security/v1/oauth/token",
                headers=ups_headers,
                data=ups_data,
            ).content
        )["access_token"]

        # get fedex access_token
        fedex_payload = {
            "grant_type": "client_credentials",
            "client_id": os.getenv("FEDEX_CLIENT_ID"),
            "client_secret": os.getenv("FEDEX_CLIENT_SECRET"),
        }
        fedex_headers = {
            "Content-Type": "application/x-www-form-urlencoded",
        }

        fedex_access_token = json.loads(
            session.post(
                "https://apis.fedex.com/oauth/token",
                data=fedex_payload,
                headers=fedex_headers,
            ).text
        )["access_token"]
        startTime = time.time()


login()
main_alt()
sys.exit()
