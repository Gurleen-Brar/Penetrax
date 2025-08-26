import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import sys
import io
import os
import platform
import subprocess

# === Import your modules ===
from modules.recon import run_recon_scan
from modules.vuln import run_vuln_scan

# === Redirect print to GUI + save to log file ===
class RedirectText(io.StringIO):
    def __init__(self, widget, target_ip="scan"):
        super().__init__()
        self.widget = widget
        self.log_path = f"reports/{target_ip}_gui_log.txt"
        os.makedirs("reports", exist_ok=True)
        with open(self.log_path, "w") as f:
            f.write("=== Penetrax GUI Scan Log ===\n\n")

    def write(self, string):
        self.widget.insert(tk.END, string)
        self.widget.see(tk.END)
        with open(self.log_path, "a") as f:
            f.write(string)

    def flush(self):
        pass

# === Run the selected module ===
def run_selected_module():
    output_box.delete(1.0, tk.END)
    ip = ip_entry.get().strip()
    if not ip:
        messagebox.showerror("Input Error", "Please enter a valid IP address.")
        return

    sys.stdout = RedirectText(output_box, target_ip=ip)
    module = selected_module.get()

    def threaded():
        try:
            if module == "Recon Scan":
                run_recon_scan(ip)
            elif module == "Vulnerability Scan":
                run_vuln_scan(ip)
        except Exception as e:
            print(f"[!] Error: {e}")
        finally:
            sys.stdout = sys.__stdout__

    threading.Thread(target=threaded).start()

# === Open the reports/ folder ===
def open_reports_folder():
    reports_path = os.path.abspath("reports")
    if not os.path.exists(reports_path):
        messagebox.showinfo("No Reports", "No reports found yet.")
        return

    system = platform.system()
    try:
        if system == "Linux":
            subprocess.run(["xdg-open", reports_path])
        elif system == "Darwin":
            subprocess.run(["open", reports_path])
        elif system == "Windows":
            os.startfile(reports_path)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to open folder: {e}")

# === Toggle Dark Mode ===
def toggle_dark_mode():
    if style.theme_use() == "clam":
        app.configure(bg="#2e2e2e")
        style.configure("TLabel", background="#2e2e2e", foreground="#ffffff")
        style.configure("TButton", background="#444444", foreground="white")
        style.configure("TCombobox", fieldbackground="#444444", background="#444444", foreground="white")
        output_box.configure(bg="#1e1e1e", fg="#ffffff", insertbackground="#ffffff")
        style.theme_use("alt")
    else:
        app.configure(bg="#f0f4f8")
        style.configure("TLabel", background="#f0f4f8", foreground="black")
        style.configure("TButton", background="#007acc", foreground="white")
        style.configure("TCombobox", fieldbackground="white", background="white", foreground="black")
        output_box.configure(bg="#ffffff", fg="#000000", insertbackground="#000000")
        style.theme_use("clam")

# === GUI setup ===
app = tk.Tk()
app.title("Penetrax – Scan Interface")
app.geometry("900x600")
app.configure(bg="#f0f4f8")
app.minsize(650, 500)
app.rowconfigure(5, weight=1)
app.columnconfigure(1, weight=1)

# === Style ===
style = ttk.Style()
style.theme_use("clam")
style.configure("TLabel", background="#f0f4f8", font=("Segoe UI", 10))
style.configure("TButton", background="#007acc", foreground="white", font=("Segoe UI", 10, "bold"))
style.map("TButton", background=[("active", "#005f99")])
style.configure("TCombobox", font=("Segoe UI", 10))

# === Layout ===
ttk.Label(app, text="Select Module:").grid(row=0, column=0, padx=10, pady=5, sticky="w")
selected_module = tk.StringVar()
module_box = ttk.Combobox(app, textvariable=selected_module, width=30)
module_box['values'] = ("Recon Scan", "Vulnerability Scan")
module_box.current(0)
module_box.grid(row=0, column=1, padx=10, pady=5, sticky="ew")

ttk.Label(app, text="Target IP:").grid(row=1, column=0, padx=10, pady=5, sticky="w")
ip_entry = tk.Entry(app, width=40)
ip_entry.insert(0, "10.0.2.5")
ip_entry.grid(row=1, column=1, padx=10, pady=5, sticky="ew")

run_btn = ttk.Button(app, text="Run Scan", command=run_selected_module)
run_btn.grid(row=2, column=0, columnspan=2, pady=10)

button_frame = tk.Frame(app, bg="#f0f4f8")
button_frame.grid(row=3, column=0, columnspan=2, pady=5)

open_btn = ttk.Button(button_frame, text="📁 Open Report Folder", command=open_reports_folder)
open_btn.pack(side=tk.LEFT, padx=5)

dark_mode_btn = ttk.Button(button_frame, text="🌙 Toggle Dark Mode", command=toggle_dark_mode)
dark_mode_btn.pack(side=tk.LEFT, padx=5)

output_box = scrolledtext.ScrolledText(app, wrap=tk.WORD, font=("Courier New", 10), bg="#ffffff")
output_box.grid(row=5, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")

# === Start GUI ===
app.mainloop()
