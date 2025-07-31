import tkinter as tk
from tkinter import messagebox
from PIL import Image, ImageTk
import threading
import time
import SSL_Cert_Check

class EvilTwinScannerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SSL Certificate Scanner")
        self.geometry("500x250")
        self.configure(bg="#f2f2f2")

        self.auto_scan_running = False
        self.scanned_domains = set()

        # Logo
        try:
            image = Image.open("icon.png").resize((80, 80))
            icon = ImageTk.PhotoImage(image)
            tk.Label(self, image=icon, bg="#f2f2f2").pack(pady=10)
            self.icon = icon  # Keep reference
        except:
            tk.Label(self, text="📦", font=("Arial", 40), bg="#f2f2f2").pack(pady=10)

        # Header
        tk.Label(self, text="SSL Certificate Scanner", font=("Helvetica", 18, "bold"), bg="#f2f2f2", fg="#333").pack(pady=5)

        # Buttons
        button_frame = tk.Frame(self, bg="#f2f2f2")
        button_frame.pack(pady=10)

        tk.Button(button_frame, text="▶️ Start Scan", font=("Arial", 12), bg="#008000", fg="WHITE", width=20,
                  command=self.start_scan).grid(row=0, column=0, padx=10)
        tk.Button(button_frame, text="⏹ Stop Scan", font=("Arial", 12), bg="#FF0000", fg="WHITE", width=20,
                  command=self.stop_auto_scan).grid(row=0, column=1, padx=10)

        # Status display
        self.result_label = tk.Label(self, text="", font=("Arial", 12), bg="#f2f2f2")
        self.result_label.pack(pady=15)

    def start_scan(self):
        if not self.auto_scan_running:
            self.auto_scan_running = True
            self.result_label.config(text="🟢 Scanning started...", fg="#4CAF50")
            threading.Thread(target=self.background_auto_scan, daemon=True).start()
        else:
            messagebox.showinfo("Already Running", "Scan is already running.")

    def stop_auto_scan(self):
        self.auto_scan_running = False
        self.result_label.config(text="⛔ Scanning stopped.", fg="gray")

    def background_auto_scan(self):
        while self.auto_scan_running:
            result = SSL_Cert_Check.auto_scan_step(self.scanned_domains)
            if result:
                self.result_label.after(0, lambda r=result: self.update_result_display(r))
            time.sleep(3)

    def update_result_display(self, result):
        color = "#4CAF50" if result["status"] == "safe" else "#f44336"
        self.result_label.config(
            text=f"{'✅' if result['status']=='safe' else '❌'} {result['status'].upper()}",
            fg=color
        )
        messagebox.showinfo("Scan Result", result["details"])

if __name__ == "__main__":
    app = EvilTwinScannerApp()
    app.mainloop()
