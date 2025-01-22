import calendar
import datetime
import json
import os
import re
import sys
import time
import tkinter
from base64 import b64decode, b64encode
from tkinter import END, CENTER
import threading

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
    """Simple splash screen"""
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
    """Quit the program entirely."""
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
    # repeated obfuscation
    return obfuscate(obfuscate(obfuscate(obfuscate(obfuscate(pw)))))


def decrypt(pw):
    # reverse repeated obfuscation
    return deobfuscate(deobfuscate(deobfuscate(deobfuscate(deobfuscate(pw)))))


########################
# Global credentials   #
########################
user_name = None
password = None


def getCreds():
    """Prompt user for GP credentials if file doesn't exist or is invalid."""

    def printValue(event=None):
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
    customtkinter.CTkButton(main_frame, text="Submit", command=printValue).pack(pady=(0, 10))
    main.protocol("WM_DELETE_WINDOW", exitProg)
    main_frame.pack(padx=10, pady=(10))
    main.mainloop()


def login():
    """Attempt to load or prompt for credentials, verifying a test connection."""
    global user_name, password

    def try_connect(test_user, test_pass):
        try:
            conn = pymssql.connect(
                server="gp2018",
                user=f"GRT0\\{test_user}",
                password=test_pass,
                database="SBM01",
            )
            conn.close()
            return True
        except Exception as e:
            print(f"Connection error: {e}")
            return False

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

            if try_connect(user_name, password):
                # Save valid credentials
                if not os.path.exists("credentials.txt"):
                    with open("credentials.txt", "w") as fh:
                        fh.write(f"{encrypt(user_name)}\n")
                        fh.write(f"{encrypt(password)}")
                break
            else:
                # remove file, re-prompt
                if os.path.exists("credentials.txt"):
                    os.remove("credentials.txt")
                getCreds()

        except Exception as e:
            print(f"Login error: {e}")
            if os.path.exists("credentials.txt"):
                os.remove("credentials.txt")
            getCreds()
            user_name = None
            password = None


############################################
# Each thread gets its own DB connection   #
############################################
def get_db_connection():
    """Create a new db connection using the globally stored credentials."""
    return pymssql.connect(
        server="gp2018",
        user=f"GRT0\\{user_name}",
        password=password,
        database="SBM01",
    )


#############################
# Pre-compile Regex for speed
#############################
usps_pattern = [
    r"^(94|93|92|94|95)[0-9]{20}$",
    r"^(94|93|92|94|95)[0-9]{22}$",
    r"^(70|14|23|03)[0-9]{14}$",
    r"^(M0|82)[0-9]{8}$",
    r"^([A-Z]{2})[0-9]{9}([A-Z]{2})$",
]
ups_pattern = [
    r"^(1Z)[0-9A-Z]{16}$",
    r"^(T)+[0-9A-Z]{10}$",
    r"^[0-9]{9}$",
    r"^[0-9]{26}$",
]
fedex_pattern = [
    r"^[0-9]{20}$",
    r"^[0-9]{15}$",
    r"^[0-9]{12}$",
    r"^[0-9]{22}$",
]

usps_regex = re.compile("(" + ")|(".join(usps_pattern) + ")")
ups_regex = re.compile("(" + ")|(".join(ups_pattern) + ")")
fedex_regex = re.compile("(" + ")|(".join(fedex_pattern) + ")")


def recognize_delivery_service(tracking):
    """Return 'USPS', 'UPS', 'FedEx', or None depending on the tracking format."""
    tracking = tracking.upper().strip()
    if usps_regex.match(tracking):
        return "USPS"
    elif ups_regex.match(tracking):
        return "UPS"
    elif fedex_regex.match(tracking):
        return "FedEx"
    return None


#############################################
# Setup UPS / FedEx tokens & refresh logic  #
#############################################
session = requests.Session()
session.headers.update({"Connection": "keep-alive"})

ups_headers = {
    "accept": "application/json",
    "Authorization": f"Basic {os.getenv('UPS_AUTH')}",
    "Content-Type": "application/x-www-form-urlencoded",
}
ups_data = {"grant_type": "client_credentials"}

fedex_payload = {
    "grant_type": "client_credentials",
    "client_id": os.getenv("FEDEX_CLIENT_ID"),
    "client_secret": os.getenv("FEDEX_CLIENT_SECRET"),
}
fedex_headers = {"Content-Type": "application/x-www-form-urlencoded"}

ups_access_token = None
fedex_access_token = None

startTime = time.time()
token_validity_seconds = 3000  # e.g. 50 minutes


def init_tokens():
    """Initialize the global UPS and FedEx tokens once at startup."""
    global ups_access_token, fedex_access_token, startTime

    # UPS
    ups_resp = session.post(
        "https://wwwcie.ups.com/security/v1/oauth/token",
        headers=ups_headers,
        data=ups_data,
    )
    ups_access_token = json.loads(ups_resp.content)["access_token"]

    # FedEx
    fedex_resp = session.post(
        "https://apis.fedex.com/oauth/token",
        data=fedex_payload,
        headers=fedex_headers,
    )
    fedex_access_token = json.loads(fedex_resp.text)["access_token"]

    startTime = time.time()


def refresh_tokens_if_needed():
    """Refresh UPS and FedEx tokens if older than 'token_validity_seconds'."""
    global ups_access_token, fedex_access_token, startTime

    if time.time() - startTime > token_validity_seconds:
        # Refresh UPS
        ups_resp = session.post(
            "https://wwwcie.ups.com/security/v1/oauth/token",
            headers=ups_headers,
            data=ups_data,
        )
        ups_access_token = json.loads(ups_resp.content)["access_token"]

        # Refresh FedEx
        fedex_resp = session.post(
            "https://apis.fedex.com/oauth/token",
            data=fedex_payload,
            headers=fedex_headers,
        )
        fedex_access_token = json.loads(fedex_resp.text)["access_token"]

        startTime = time.time()


###################################################
# Single-ticket logic extracted for concurrency   #
###################################################
def track_single_ticket(ticket, text_widget, main_window):
    """
    Process a single ticket in a separate thread:
      1) Connect to DB, query for the tracking
      2) Determine shipper
      3) Request shipping data
      4) Immediately update text_widget via main_window.after
    """
    refresh_tokens_if_needed()
    tkt = ticket.strip()

    lines = []
    lines.append(f"Ticket: {tkt}")

    # Step 1: Query DB for tracking number (using a brand new connection!)
    try:
        with get_db_connection() as local_conn:
            local_cursor = local_conn.cursor()
            local_cursor.execute(
                f"""DECLARE @ticket AS VARCHAR(100) = '{tkt}'
SELECT DISTINCT
    COALESCE(sop10107.SOPNUMBE, sop30200.SOPNUMBE, sop10100.SOPNUMBE) AS SOPNUMBE,
    Tracking_Number,
    COALESCE(sop10100.BACHNUMB, sop30200.BACHNUMB) AS BACHNUMB
FROM SOP10107
FULL JOIN sop10100 ON sop10100.SOPNUMBE = sop10107.SOPNUMBE
FULL JOIN sop30200 ON sop30200.SOPNUMBE = sop10107.SOPNUMBE
WHERE
((sop10100.SOPNUMBE = @ticket OR sop10100.SOPNUMBE = 'CW' + @ticket + '-1')
OR (sop30200.SOPNUMBE = @ticket OR sop30200.SOPNUMBE = 'CW' + @ticket + '-1')
OR (sop10107.SOPNUMBE = @ticket OR sop10107.SOPNUMBE = 'CW' + @ticket + '-1'))"""
            )
            try:
                sql_row = local_cursor.fetchone()
                if sql_row and sql_row[1]:
                    inquiry_number = sql_row[1].strip().upper()
                else:
                    inquiry_number = None
            except:
                inquiry_number = None

    except Exception as db_ex:
        # If the query or connection fails, show an error
        lines.append(f"Database error: {db_ex}")
        lines.append("")
        post_result_to_gui(lines, text_widget, main_window)
        return

    if inquiry_number:
        lines.append(f"Tracking number: {inquiry_number}")
    else:
        # Possibly ticket not found or no tracking
        try:
            if sql_row and sql_row[2].strip() == "RDY TO INVOICE":
                lines.append(
                    "Status: RDY TO INVOICE - No tracking available. Possibly partial shipment."
                )
            else:
                lines.append("Status: Ticket not found or no tracking assigned.")
        except:
            lines.append("Status: Ticket not found.")
        lines.append("")
        post_result_to_gui(lines, text_widget, main_window)
        return

    # Step 2: Recognize shipper & request shipping data
    shipper = recognize_delivery_service(inquiry_number)
    status = None
    est_date_str = None

    if shipper == "UPS":
        headers = {
            "accept": "*/*",
            "transId": tkt,
            "transactionSrc": "testing",
            "Authorization": f"Bearer {ups_access_token}",
            "Content-Type": "application/json",
        }
        params = {"locale": "en_US", "returnSignature": "false"}
        tracking_info = session.get(
            f"https://onlinetools.ups.com/api/track/v1/details/{inquiry_number}",
            params=params,
            headers=headers,
        ).content
        try:
            tracking_json = json.loads(tracking_info)
            status = tracking_json["trackResponse"]["shipment"][0]["package"][0]["activity"][0]["status"][
                "description"].strip()
            # Attempt to retrieve delivery date
            try:
                del_date = tracking_json["trackResponse"]["shipment"][0]["package"][0]["deliveryDate"][0]["date"]
                del_date_dt = datetime.datetime.strptime(del_date, "%Y%m%d")
                del_date_str = (
                    f"{calendar.month_name[del_date_dt.month]} {del_date_dt.day}, {del_date_dt.year}"
                )
                del_time = tracking_json["trackResponse"]["shipment"][0]["package"][0]["deliveryTime"]["type"].strip()
                if del_time == "CMT":
                    del_time = "AM"
                est_date_str = f"{del_date_str} by {del_time}"
            except:
                est_date_str = "No specific date available yet."
        except:
            status = (
                "We could not locate the shipment details (check if older than 120 days or invalid)."
            )

    elif shipper == "FedEx":
        payload = json.dumps({
            "trackingInfo": [{"trackingNumberInfo": {"trackingNumber": inquiry_number}}],
            "includeDetailedScans": False,
        })
        headers = {
            "Content-Type": "application/json",
            "x-customer-transaction-id": tkt,
            "X-locale": "en_US",
            "Authorization": f"Bearer {fedex_access_token}",
        }
        response = session.post(
            "https://apis.fedex.com/track/v1/trackingnumbers",
            data=payload,
            headers=headers
        )
        try:
            res_json = json.loads(response.content)
            status = res_json["output"]["completeTrackResults"][0]["trackResults"][0]["latestStatusDetail"][
                "statusByLocale"]
            del_date_str = res_json["output"]["completeTrackResults"][0]["trackResults"][0]["dateAndTimes"][0][
                "dateTime"]
            # Example: "2025-01-01T09:00:00-05:00"
            dt_split = del_date_str.split("T")
            if len(dt_split) == 2:
                date_part, time_part = dt_split
                date_part = date_part.replace("-", "")  # "20250101"
                del_date_dt = datetime.datetime.strptime(date_part, "%Y%m%d")
                pretty_date = f"{calendar.month_name[del_date_dt.month]} {del_date_dt.day}, {del_date_dt.year}"
                time_part = time_part.split("-")[0]  # remove timezone offset
                short_time = time_part.split(":")[0:2]
                short_time_str = ":".join(short_time)
                if short_time_str == "00:00":
                    short_time_str = "EOD"
                est_date_str = f"{pretty_date} by {short_time_str}"
        except:
            status = "FedEx details not found or invalid. Try again later."

    elif shipper == "USPS":
        status = "USPS tracking not fully implemented."
        est_date_str = None

    else:
        status = "Unrecognized or invalid tracking format."

    # Step 3: Build final lines
    if status:
        lines.append(f"Status: {status}")

    if status and "delivered" in status.lower():
        if est_date_str:
            lines.append(f"Delivery date: {est_date_str}")
    else:
        if est_date_str:
            lines.append(f"Estimated delivery: {est_date_str}")

    lines.append("")
    post_result_to_gui(lines, text_widget, main_window)


def post_result_to_gui(lines, text_widget, main_window):
    """Safely update Tk widgets from a worker thread via main_window.after."""

    def insert_lines():
        for line in lines:
            text_widget.insert(END, line + "\n")
        text_widget.see("end")  # auto-scroll

    main_window.after(0, insert_lines)


#########################
# Main program UI logic #
#########################
def main_alt():
    """
    Main window that uses threading to process tickets
    so results appear as soon as each ticket is done.
    Keeps "Processing..." label until all threads finish.
    Now also ensures default text is cleared on the first run.
    """
    cleared = False
    first_run = True  # NEW FLAG
    thread_count = 0  # how many threads are still running

    def on_thread_done():
        nonlocal thread_count
        thread_count -= 1
        if thread_count <= 0:
            button.configure(text="Submit")

    def start_thread_for_ticket(ticket_number):
        def worker():
            track_single_ticket(ticket_number, text, main)
            main.after(0, on_thread_done)
        thr = threading.Thread(target=worker)
        thr.start()

    def actual_print():
        nonlocal cleared, thread_count, first_run

        tkt = ticket.get("1.0", "end-1c")
        local_list = tkt.replace(",", " ").replace("\n", " ").split()

        # ALWAYS clear text on the very first run
        if first_run:
            text.delete("0.0", "end")
            first_run = False
        elif cleared:
            text.delete("0.0", "end")
            cleared = False

        text.configure(text_color="white")
        button.configure(text="Processing...")

        thread_count = len(local_list)
        if thread_count == 0:
            button.configure(text="Submit")
            return

        for tk_ in local_list:
            start_thread_for_ticket(tk_)

    def printValue(event):
        actual_print()

    def printValue2():
        actual_print()

    def clear():
        nonlocal cleared
        text.delete("0.0", "end")
        ticket.delete("0.0", "end")
        text.configure(text_color="gray")
        insert_initial()
        cleared = True

    def endProg():
        sys.exit()

    def insert_initial():
        text.configure(text_color="gray")
        try:
            joke = requests.get("https://icanhazdadjoke.com", headers={"Accept": "application/json"}).json()["joke"]
        except:
            joke = "No joke available."
        initial_text = f"""Enter the ticket numbers above separated by commas, spaces, or line-breaks.





Random dad joke:

{joke.strip()}





Created by Mikey Marcotte"""
        text.tag_config("tag-center", justify=CENTER)
        text.insert(END, initial_text, "tag-center")

    # --- Create the main Tk window ---
    main = customtkinter.CTk()
    main.title("  Granite QuickTracker")
    main.wm_iconbitmap(granite_icon)
    main.attributes("-alpha", 0.95)
    center_win(main)

    main_frame = customtkinter.CTkFrame(master=main)
    customtkinter.CTkLabel(master=main_frame, text="Please enter the ticket number(s):").pack(pady=(20, 0), padx=108)

    ticket = customtkinter.CTkTextbox(master=main_frame, width=270, height=70)
    ticket.pack(padx=10, pady=10)
    main.bind("<Return>", printValue)

    button = customtkinter.CTkButton(master=main_frame, text="Submit", command=printValue2)
    button.pack(padx=10, pady=(0, 10))
    main.protocol("WM_DELETE_WINDOW", endProg)
    main_frame.pack(padx=10, pady=10)

    # Output text area
    win_frame = customtkinter.CTkFrame(main)
    text = customtkinter.CTkTextbox(master=win_frame, wrap=tkinter.WORD, width=400, height=300, text_color="gray")
    text.pack(padx=10, pady=10)

    insert_initial()

    customtkinter.CTkButton(master=win_frame, text="Clear", width=100, command=clear).pack(
        side="left", anchor="ne", expand=True, padx=5, pady=(0, 10)
    )
    customtkinter.CTkButton(master=win_frame, text="Exit", width=100, command=endProg).pack(
        side="right", anchor="nw", expand=True, padx=5, pady=(0, 10)
    )

    win_frame.pack(padx=10, pady=(0, 10))
    main.mainloop()



if __name__ == "__main__":
    login()  # Prompt / load credentials
    init_tokens()  # Initialize UPS / FedEx tokens
    main_alt()  # Show the main application
    sys.exit()
