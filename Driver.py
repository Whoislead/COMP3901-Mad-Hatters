import tkinter as tk
from tkinter import Canvas, PhotoImage
from PIL import Image, ImageTk

root = tk.Tk()
root.title("Evil Twin Detector")
root.geometry("900x600")
root.configure(bg="#00008B")

canvas = Canvas(root, width=900, height=600, bg="#00008B", highlightthickness=0)
canvas.place(x=0, y=0)

vector_img = Image.open("Frontend/images/Vector 2.png")
vector_photo = ImageTk.PhotoImage(vector_img)
canvas.create_image(0, 1000, image=vector_photo, anchor="sw")

try:
    logo_img = Image.open("Frontend/images/Untitled design 1.png")
    logo_img = logo_img.resize((80, 100), Image.Resampling.LANCZOS)
    logo = ImageTk.PhotoImage(logo_img)
    canvas.create_image(700, 100, image=logo)
except Exception as e:
    pass

# Title text
canvas.create_text(700, 180, text="EVIL TWIN DETECTOR", font=("Helvetica", 20, "bold"), fill="black")
canvas.create_text(650, 250, text="Welcome", font=("Helvetica", 24, "bold"), fill="white")

# Navigation buttons
button_style = {"font": ("Helvetica", 14), "bg": "#000000", "fg": "white", "borderwidth": 0}

home_btn = tk.Button(root, text="Home", **button_style)
home_btn.place(x=60, y=550)

account_btn = tk.Button(root, text="Account", **button_style)
account_btn.place(x=300, y=550)

scan_btn = tk.Button(root, text="Scan", **button_style)
scan_btn.place(x=530, y=550)

about_btn = tk.Button(root, text="About", **button_style)
about_btn.place(x=750, y=550)

def open_about():
    about_win = tk.Toplevel(root)
    about_win.title("About")
    about_win.geometry("600x500")
    about_win.configure(bg="#00008B")  # Deep blue background

    # Container Frame for padding and layout
    #content_frame = tk.Frame(about_win, bg="#00008B")
    #content_frame.pack(fill="both", expand=True, padx=20, pady=20)

    # Heading
    heading = tk.Label(about_win, text="Evil Twin Detector", font=("Helvetica", 24, "bold"), fg="white", bg="#00008B")
    heading.pack(pady=20)

    # Default about text
    about_text = """  
    An evil twin attack is an event where a bad actor creates a fake access point that imitates a legitimate one with the aim of collecting user credentials, logins or oteher personal data.

    Evil Twin Detetor is designed to help everyday users detect Wi-Fi connections that are suspicious or imitating trusted networks. These networks can be captured using SSL certificates and beacon frames which would alert users to malicious WiFI before connecting.

    Our mission is to help protect users on all levels by providing tools that make Wi-Fi security accessible to everyone.
    """
    about_label = tk.Label(about_win, text=about_text, font=("Helvetica", 14), fg="white", bg="#00008B", justify="left", wraplength=550)
    about_label.pack(padx=20)

    # Close button
    close_btn = tk.Button(about_win, text="Close", font=("Helvetica", 14), bg="#000000", fg="white", borderwidth=0, command=about_win.destroy)
    close_btn.pack(pady=20)

# Bind the About button
about_btn.config(command=open_about)

root.mainloop()