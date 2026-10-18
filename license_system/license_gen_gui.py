#!/usr/bin/env python3
"""
Python Tkinter Desktop GUI for Offline Ed25519 License Key Generator
"""

import sys
import os
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime, timezone, timedelta

# Import core generator logic
from license_gen import ensure_keypair, generate_license, DEFAULT_PRODUCT_ID, DURATION_OPTIONS

class KeyGenApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Ed25519 Offline License Generator (Admin)")
        self.root.geometry("600x520")
        self.root.resizable(False, False)

        # Style dark theme
        self.root.configure(bg="#181c24")
        self.style = ttk.Style()
        self.style.theme_use("clam")

        self.private_key, self.public_key = ensure_keypair()
        self.create_widgets()

    def create_widgets(self):
        # Header
        lbl_title = tk.Label(self.root, text="ED25519 OFFLINE LICENSE GENERATOR",
                             font=("Segoe UI", 13, "bold"), fg="#34d399", bg="#181c24")
        lbl_title.pack(anchor="w", padx=25, pady=(20, 2))

        lbl_sub = tk.Label(self.root, text="Generate cryptographically signed offline keys for your Game Mod",
                           font=("Segoe UI", 9), fg="#9ca3af", bg="#181c24")
        lbl_sub.pack(anchor="w", padx=25, pady=(0, 15))

        # Form Frame
        form_frame = tk.Frame(self.root, bg="#181c24")
        form_frame.pack(fill="x", padx=25)

        # Product ID
        tk.Label(form_frame, text="Product ID:", font=("Segoe UI", 9, "bold"), fg="#e5e7eb", bg="#181c24").grid(row=0, column=0, sticky="w", pady=4)
        self.ent_product = tk.Entry(form_frame, width=30, font=("Consolas", 10), bg="#232834", fg="#ffffff", insertbackground="white", relief="flat")
        self.ent_product.insert(0, DEFAULT_PRODUCT_ID)
        self.ent_product.grid(row=1, column=0, sticky="w", padx=(0, 20), pady=(0, 10))

        # Duration
        tk.Label(form_frame, text="Duration:", font=("Segoe UI", 9, "bold"), fg="#e5e7eb", bg="#181c24").grid(row=0, column=1, sticky="w", pady=4)
        self.var_dur = tk.StringVar(value="7-day")
        dur_combo = ttk.Combobox(form_frame, textvariable=self.var_dur, state="readonly", width=25,
                                 values=["1-day (24h)", "7-day (1 Week)", "30-day (1 Month)", "90-day (Quarterly)", "365-day (1 Year)", "lifetime (No Expiry)"])
        dur_combo.current(1)
        dur_combo.grid(row=1, column=1, sticky="w", pady=(0, 10))

        # Generate Button
        btn_gen = tk.Button(self.root, text="GENERATE LICENSE KEY", font=("Segoe UI", 10, "bold"),
                            bg="#10b981", fg="white", activebackground="#059669", activeforeground="white",
                            relief="flat", cursor="hand2", command=self.on_generate)
        btn_gen.pack(fill="x", padx=25, pady=15, ipady=6)

        # Key Output
        tk.Label(self.root, text="Customer License Key (LIC-1 format):", font=("Segoe UI", 9, "bold"),
                 fg="#e5e7eb", bg="#181c24").pack(anchor="w", padx=25, pady=(5, 4))

        self.txt_output = tk.Text(self.root, height=5, font=("Consolas", 9), bg="#0f141c", fg="#6ee7b7",
                                  wrap="char", relief="flat", padx=10, pady=10)
        self.txt_output.pack(fill="x", padx=25)

        # Meta details & copy
        bottom_frame = tk.Frame(self.root, bg="#181c24")
        bottom_frame.pack(fill="x", padx=25, pady=15)

        btn_copy = tk.Button(bottom_frame, text="Copy Key to Clipboard", font=("Segoe UI", 9, "bold"),
                             bg="#3b82f6", fg="white", activebackground="#2563eb", activeforeground="white",
                             relief="flat", cursor="hand2", command=self.on_copy)
        btn_copy.pack(side="left", padx=(0, 15), ipady=4, ipadx=8)

        self.lbl_status = tk.Label(bottom_frame, text="Ready.", font=("Segoe UI", 9), fg="#9ca3af", bg="#181c24")
        self.lbl_status.pack(side="left", pady=4)

    def on_generate(self):
        prod_id = self.ent_product.get().strip() or DEFAULT_PRODUCT_ID
        dur_sel = self.var_dur.get()

        delta = None
        dur_type = "7-day"
        if "1-day" in dur_sel:
            dur_type = "1-day"; delta = timedelta(days=1)
        elif "7-day" in dur_sel:
            dur_type = "7-day"; delta = timedelta(days=7)
        elif "30-day" in dur_sel:
            dur_type = "30-day"; delta = timedelta(days=30)
        elif "90-day" in dur_sel:
            dur_type = "90-day"; delta = timedelta(days=90)
        elif "365-day" in dur_sel:
            dur_type = "365-day"; delta = timedelta(days=365)
        elif "lifetime" in dur_sel:
            dur_type = "lifetime"; delta = None

        payload, key = generate_license(self.private_key, dur_type, delta, prod_id)

        self.txt_output.delete("1.0", tk.END)
        self.txt_output.insert(tk.END, key)

        if payload["expires_at"] > 0:
            exp_str = datetime.fromtimestamp(payload["expires_at"], timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M")
        else:
            exp_str = "Lifetime"

        self.lbl_status.config(text=f"Generated {dur_type} key! Expires: {exp_str}", fg="#34d399")

    def on_copy(self):
        key = self.txt_output.get("1.0", tk.END).strip()
        if key:
            self.root.clipboard_clear()
            self.root.clipboard_append(key)
            self.lbl_status.config(text="Key copied to clipboard!", fg="#34d399")

if __name__ == "__main__":
    root = tk.Tk()
    app = KeyGenApp(root)
    root.mainloop()
