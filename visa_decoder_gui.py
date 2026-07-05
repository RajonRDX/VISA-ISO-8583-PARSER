"""
VisaNet Authorization-Only  ISO 8583  Message Decoder  —  GUI Edition
VisaNet Authorization-Only Online Messages Technical Specifications (Eff. 20 Apr 2026)

Standalone GUI: paste raw hex / log fragment → parse → export TXT + Excel

IMPORTANT — how this file relates to visa_iso8583_parser_v1.py:
  This module does NOT reimplement any ISO 8583 / VisaNet parsing logic.
  All decoding is delegated to visa_iso8583_parser_v1.py (unmodified) via
  the shared visa_adapter.py module, which is also used by the Flask web
  front end (app.py). Everything in this file is Tkinter presentation
  code only.
"""

import sys, os, threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

# -- shared, UI-toolkit-agnostic adapter (imports the untouched parser) -----
import visa_iso8583_parser_v1 as visa_parser
from visa_adapter import (
    HAS_OPENPYXL,
    VISA_MTI_NAMES,
    decode_visa_message,
    _prepare_hex_input,
    _first_val,
    _fields_by_num,
    _extract_rrn,
    _extract_mti,
)




# ═══════════════════════════════════════════════════════════════════════════════
# GUI  (design / layout / behaviour mirrors w4_decoder_gui.py's WAY4DecoderApp)
# ═══════════════════════════════════════════════════════════════════════════════
class VisaDecoderApp:
    BG = "#0D1B2A"; BG2 = "#162233"; BG3 = "#1E2E42"
    ACCENT = "#00C8A0"; ACCENT2 = "#007A70"
    HIGHLIGHT = "#FFB400"; SUCCESS = "#2ECC71"; WARNING = "#F39C12"; ERROR = "#E74C3C"
    TEXT = "#E4EEF8"; TEXT_DIM = "#5A7A99"; BORDER = "#243550"

    FONT_MONO = ("Consolas", 10); FONT_UI = ("Segoe UI", 10)
    FONT_BOLD = ("Segoe UI", 10, "bold"); FONT_H1 = ("Segoe UI", 14, "bold"); FONT_H2 = ("Segoe UI", 11, "bold")

    def __init__(self, root):
        self.root = root
        self.root.title("VisaNet ISO 8583 Decoder  —  VisaNet Authorization-Only Online Messages")
        self.root.configure(bg=self.BG)
        self.root.geometry("1300x880"); self.root.minsize(900, 640)
        self._last_result = None; self._last_warnings = []; self._last_compact = ""
        self._last_rows = []; self._last_raw_input = ""
        self._output_folder = tk.StringVar(value=os.path.join(os.path.expanduser("~"), "VISA_Output"))
        self._build_ui()
        self._status("Ready — paste raw VisaNet hex or log fragment and press  Parse  ↵")

    def _build_ui(self):
        self._build_titlebar()
        main = tk.Frame(self.root, bg=self.BG); main.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        main.columnconfigure(0, weight=4, minsize=320); main.columnconfigure(1, weight=6, minsize=400)
        main.columnconfigure(2, weight=2, minsize=200); main.rowconfigure(0, weight=1)
        self._build_input_panel(main); self._build_output_panel(main); self._build_sidebar(main)
        self._build_statusbar()

    def _build_titlebar(self):
        bar = tk.Frame(self.root, bg=self.ACCENT2, height=56); bar.pack(fill="x"); bar.pack_propagate(False)
        logo = tk.Frame(bar, bg=self.ACCENT2); logo.pack(side="left", padx=16)
        tk.Label(logo, text="⬡", font=("Segoe UI", 22), fg=self.ACCENT, bg=self.ACCENT2).pack(side="left")
        tk.Label(logo, text=" VisaNet  ISO 8583 Decoder", font=self.FONT_H1, fg=self.TEXT, bg=self.ACCENT2).pack(side="left", padx=6)
        tk.Label(bar, text="VisaNet Authorization-Only Online Messages  ·  Eff. 20 Apr 2026",
                 font=("Segoe UI", 9), fg="#90B4CC", bg=self.ACCENT2).pack(side="right", padx=16)

    def _build_input_panel(self, parent):
        frame = tk.Frame(parent, bg=self.BG2); frame.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        frame.rowconfigure(1, weight=1); frame.columnconfigure(0, weight=1)
        hdr = tk.Frame(frame, bg=self.BG2); hdr.grid(row=0, column=0, sticky="ew", padx=12, pady=(12, 6))
        tk.Label(hdr, text="▸ Raw Hex Input", font=self.FONT_H2, fg=self.ACCENT, bg=self.BG2).pack(side="left")
        self._make_btn(hdr, "✕ Clear", self._clear_input, "flat").pack(side="right")
        self._make_btn(hdr, "📂 Load File", self._load_file, "flat").pack(side="right", padx=(0, 6))
        ta_frame = tk.Frame(frame, bg=self.BORDER, bd=1); ta_frame.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0, 8))
        ta_frame.rowconfigure(0, weight=1); ta_frame.columnconfigure(0, weight=1)
        self.input_text = tk.Text(ta_frame, font=self.FONT_MONO, bg=self.BG3, fg=self.TEXT,
                                   insertbackground=self.ACCENT, relief="flat", bd=0,
                                   selectbackground=self.ACCENT2, wrap="word", undo=True)
        self.input_text.grid(row=0, column=0, sticky="nsew")
        sb = ttk.Scrollbar(ta_frame, orient="vertical", command=self.input_text.yview)
        sb.grid(row=0, column=1, sticky="ns"); self.input_text.configure(yscrollcommand=sb.set)
        self._set_placeholder()
        self.input_text.bind("<FocusIn>", self._clear_placeholder)
        self.input_text.bind("<FocusOut>", self._check_placeholder)
        self.btn_parse = tk.Button(frame, text="⚡  PARSE MESSAGE", font=("Segoe UI", 11, "bold"),
                                    bg=self.ACCENT, fg="#0D1B2A", activebackground=self.ACCENT2,
                                    activeforeground=self.TEXT, relief="flat", bd=0, cursor="hand2",
                                    command=self._parse, padx=20, pady=10)
        self.btn_parse.grid(row=2, column=0, sticky="ew", padx=12, pady=(0, 12))
        self.root.bind("<Control-Return>", lambda e: self._parse())

    def _build_output_panel(self, parent):
        frame = tk.Frame(parent, bg=self.BG2); frame.grid(row=0, column=1, sticky="nsew", padx=(0, 8))
        frame.rowconfigure(1, weight=1); frame.columnconfigure(0, weight=1)
        hdr = tk.Frame(frame, bg=self.BG2); hdr.grid(row=0, column=0, sticky="ew", padx=12, pady=(12, 0))
        tk.Label(hdr, text="▸ Decoded Output", font=self.FONT_H2, fg=self.ACCENT, bg=self.BG2).pack(side="left")
        self._make_btn(hdr, "⎘ Copy", self._copy_output, "flat").pack(side="right")
        style = ttk.Style(); style.theme_use("clam")
        style.configure("Visa.TNotebook", background=self.BG2, borderwidth=0)
        style.configure("Visa.TNotebook.Tab", background=self.BG3, foreground=self.TEXT_DIM,
                         padding=[12, 6], font=self.FONT_UI, borderwidth=0)
        style.map("Visa.TNotebook.Tab", background=[("selected", self.ACCENT2)], foreground=[("selected", self.TEXT)])
        nb = ttk.Notebook(frame, style="Visa.TNotebook"); nb.grid(row=1, column=0, sticky="nsew", padx=12, pady=(6, 12))
        frame.rowconfigure(1, weight=1); self.notebook = nb
        # Tab 1 – Detailed
        tab1 = tk.Frame(nb, bg=self.BG3); nb.add(tab1, text=" Detailed View ")
        tab1.rowconfigure(0, weight=1); tab1.columnconfigure(0, weight=1)
        self.output_text = tk.Text(tab1, font=self.FONT_MONO, bg=self.BG3, fg=self.TEXT,
                                    relief="flat", bd=0, state="disabled",
                                    selectbackground=self.ACCENT2, wrap="none")
        self.output_text.grid(row=0, column=0, sticky="nsew")
        sb1v = ttk.Scrollbar(tab1, orient="vertical", command=self.output_text.yview)
        sb1h = ttk.Scrollbar(tab1, orient="horizontal", command=self.output_text.xview)
        sb1v.grid(row=0, column=1, sticky="ns"); sb1h.grid(row=1, column=0, sticky="ew")
        self.output_text.configure(yscrollcommand=sb1v.set, xscrollcommand=sb1h.set)
        # Tab 2 – Compact
        tab2 = tk.Frame(nb, bg=self.BG3); nb.add(tab2, text=" Compact Output ")
        tab2.rowconfigure(0, weight=1); tab2.columnconfigure(0, weight=1)
        self.compact_text = tk.Text(tab2, font=self.FONT_MONO, bg=self.BG3, fg=self.HIGHLIGHT,
                                     relief="flat", bd=0, state="disabled",
                                     selectbackground=self.ACCENT2, wrap="word")
        self.compact_text.grid(row=0, column=0, sticky="nsew")
        sb2 = ttk.Scrollbar(tab2, orient="vertical", command=self.compact_text.yview)
        sb2.grid(row=0, column=1, sticky="ns"); self.compact_text.configure(yscrollcommand=sb2.set)
        # Tab 3 – Tree
        tab3 = tk.Frame(nb, bg=self.BG3); nb.add(tab3, text=" Fields Table ")
        tab3.rowconfigure(0, weight=1); tab3.columnconfigure(0, weight=1)
        self._build_tree(tab3)
        # tags
        self.output_text.tag_configure("header", foreground=self.ACCENT, font=("Segoe UI", 11, "bold"))
        self.output_text.tag_configure("section", foreground=self.ACCENT, font=("Consolas", 10, "bold"))
        self.output_text.tag_configure("field", foreground="#7EC8E3", font=("Consolas", 10, "bold"))
        self.output_text.tag_configure("key", foreground=self.TEXT_DIM, font=("Consolas", 9))
        self.output_text.tag_configure("value", foreground=self.TEXT, font=("Consolas", 10))
        self.output_text.tag_configure("note", foreground="#607D8B", font=("Consolas", 9, "italic"))
        self.output_text.tag_configure("warning", foreground=self.WARNING)
        self.output_text.tag_configure("error", foreground=self.ERROR)
        self.output_text.tag_configure("mti", foreground=self.HIGHLIGHT, font=("Consolas", 11, "bold"))
        self.output_text.tag_configure("sep", foreground=self.BORDER)
        self.output_text.tag_configure("bitmap", foreground="#A8D8EA")

    def _build_tree(self, parent):
        style = ttk.Style()
        style.configure("Visa.Treeview", background=self.BG3, foreground=self.TEXT,
                         fieldbackground=self.BG3, borderwidth=0, rowheight=22, font=self.FONT_MONO)
        style.configure("Visa.Treeview.Heading", background=self.ACCENT2, foreground=self.TEXT,
                         font=self.FONT_BOLD, relief="flat")
        style.map("Visa.Treeview", background=[("selected", self.ACCENT2)])
        cols = ("field", "name", "subfield", "value")
        self.tree = ttk.Treeview(parent, columns=cols, show="headings", style="Visa.Treeview")
        self.tree.heading("field", text="Field"); self.tree.heading("name", text="Name")
        self.tree.heading("subfield", text="Sub-Field / Key"); self.tree.heading("value", text="Value")
        self.tree.column("field", width=70, stretch=False, anchor="center")
        self.tree.column("name", width=210, stretch=False)
        self.tree.column("subfield", width=230, stretch=False)
        self.tree.column("value", width=400, stretch=True)
        sbv = ttk.Scrollbar(parent, orient="vertical", command=self.tree.yview)
        sbh = ttk.Scrollbar(parent, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=sbv.set, xscrollcommand=sbh.set)
        self.tree.grid(row=0, column=0, sticky="nsew"); sbv.grid(row=0, column=1, sticky="ns"); sbh.grid(row=1, column=0, sticky="ew")

    def _build_sidebar(self, parent):
        frame = tk.Frame(parent, bg=self.BG2); frame.grid(row=0, column=2, sticky="nsew")
        frame.columnconfigure(0, weight=1)
        tk.Label(frame, text="▸ Quick Summary", font=self.FONT_H2, fg=self.ACCENT, bg=self.BG2).pack(anchor="w", padx=12, pady=(12, 6))
        sf = tk.Frame(frame, bg=self.BG2); sf.pack(fill="x", padx=12)
        self._sum_mti = self._make_card(sf, "MTI", "—")
        self._sum_proc = self._make_card(sf, "Proc. Code", "—")
        self._sum_amt = self._make_card(sf, "Amount", "—")
        self._sum_rrn = self._make_card(sf, "RRN", "—")
        self._sum_resp = self._make_card(sf, "Response", "—")
        self._sum_stan = self._make_card(sf, "STAN", "—")
        self._sum_pan = self._make_card(sf, "PAN", "—")
        self._sum_term = self._make_card(sf, "Terminal", "—")
        self._sum_warnc = self._make_card(sf, "Warnings", "0")
        tk.Frame(frame, bg=self.BORDER, height=1).pack(fill="x", padx=12, pady=8)
        tk.Label(frame, text="▸ Output Folder", font=self.FONT_H2, fg=self.ACCENT, bg=self.BG2).pack(anchor="w", padx=12, pady=(0, 4))
        ff = tk.Frame(frame, bg=self.BG2); ff.pack(fill="x", padx=12); ff.columnconfigure(0, weight=1)
        tk.Entry(ff, textvariable=self._output_folder, font=("Segoe UI", 9), bg=self.BG3,
                 fg=self.TEXT, insertbackground=self.ACCENT, relief="flat", bd=4).grid(row=0, column=0, sticky="ew")
        self._make_btn(ff, "…", self._choose_folder, "flat").grid(row=0, column=1, padx=(4, 0))
        tk.Frame(frame, bg=self.BORDER, height=1).pack(fill="x", padx=12, pady=8)
        tk.Label(frame, text="▸ Export", font=self.FONT_H2, fg=self.ACCENT, bg=self.BG2).pack(anchor="w", padx=12, pady=(0, 6))
        self._make_btn(frame, "💾 Save TXT Report", self._save_txt, "normal").pack(fill="x", padx=12, pady=(0, 4))
        self._make_btn(frame, "📊 Save Excel Workbook", self._save_xlsx, "normal").pack(fill="x", padx=12, pady=(0, 4))
        self._make_btn(frame, "⬇ Save Both (TXT + Excel)", self._save_both, "accent").pack(fill="x", padx=12, pady=(0, 4))
        if not HAS_OPENPYXL:
            tk.Label(frame, text="⚠ openpyxl not installed\n  Excel export disabled",
                     font=("Segoe UI", 8), fg=self.WARNING, bg=self.BG2, justify="left").pack(anchor="w", padx=14)

    def _build_statusbar(self):
        bar = tk.Frame(self.root, bg="#0A1220", height=26); bar.pack(fill="x", side="bottom"); bar.pack_propagate(False)
        self.status_var = tk.StringVar()
        tk.Label(bar, textvariable=self.status_var, font=("Segoe UI", 9), fg=self.TEXT_DIM, bg="#0A1220", anchor="w").pack(side="left", padx=10)
        tk.Label(bar, text="VisaNet  ·  ISO 8583  ·  Authorization-Only Online Messages",
                 font=("Segoe UI", 8), fg="#2A4060", bg="#0A1220").pack(side="right", padx=10)

    def _make_btn(self, parent, text, cmd, style="flat"):
        colours = {"flat": (self.BG3, self.TEXT, self.ACCENT2),
                   "normal": (self.ACCENT2, self.TEXT, self.ACCENT),
                   "accent": (self.ACCENT, "#0D1B2A", "#00A080")}
        bg, fg, abg = colours.get(style, colours["flat"])
        return tk.Button(parent, text=text, command=cmd, font=self.FONT_UI,
                          bg=bg, fg=fg, activebackground=abg, activeforeground=self.TEXT,
                          relief="flat", bd=0, cursor="hand2", padx=10, pady=5)

    def _make_card(self, parent, label, value):
        row = tk.Frame(parent, bg=self.BG3, pady=4); row.pack(fill="x", pady=2)
        tk.Label(row, text=label, font=("Segoe UI", 8), fg=self.TEXT_DIM, bg=self.BG3, width=12, anchor="w").pack(side="left", padx=(8, 4))
        lbl = tk.Label(row, text=value, font=("Consolas", 9, "bold"), fg=self.TEXT, bg=self.BG3, anchor="w")
        lbl.pack(side="left", fill="x", expand=True, padx=(0, 8))
        return lbl

    PLACEHOLDER = "Paste raw VisaNet ISO 8583 hex dump or log fragment here…\nExample: 3230303030313031383030…  (header + MTI + bitmaps + fields, hex-encoded)"

    def _set_placeholder(self):
        self.input_text.config(fg=self.TEXT_DIM); self.input_text.insert("1.0", self.PLACEHOLDER); self._ph = True

    def _clear_placeholder(self, e=None):
        if getattr(self, "_ph", False):
            self.input_text.delete("1.0", "end"); self.input_text.config(fg=self.TEXT); self._ph = False

    def _check_placeholder(self, e=None):
        if not self.input_text.get("1.0", "end").strip():
            self._set_placeholder()

    def _status(self, msg):
        self.status_var.set(f"  {msg}")

    def _clear_input(self):
        self.input_text.delete("1.0", "end"); self._set_placeholder()

    def _load_file(self):
        path = filedialog.askopenfilename(title="Open VisaNet message file",
                                           filetypes=[("Text files", "*.txt"), ("Log files", "*.log"), ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                data = f.read()
            self._clear_placeholder(); self.input_text.delete("1.0", "end")
            self.input_text.insert("1.0", data); self._ph = False
            self._status(f"Loaded: {path}")
        except Exception as e:
            messagebox.showerror("Load Error", str(e))

    def _choose_folder(self):
        folder = filedialog.askdirectory(title="Choose output folder", initialdir=self._output_folder.get())
        if folder:
            self._output_folder.set(folder)

    def _copy_output(self):
        tab = self.notebook.index(self.notebook.select())
        txt = self.output_text.get("1.0", "end") if tab == 0 else self.compact_text.get("1.0", "end")
        self.root.clipboard_clear(); self.root.clipboard_append(txt)
        self._status("Copied to clipboard.")

    def _parse(self):
        raw = self.input_text.get("1.0", "end")
        if getattr(self, "_ph", False) or not raw.strip():
            self._status("⚠  No message to parse."); return
        self._last_raw_input = raw
        self._status("Parsing…"); self.btn_parse.config(state="disabled", text="⏳  Parsing…")
        self.root.update_idletasks()

        def _worker():
            try:
                result, warnings, compact = decode_visa_message(raw)
                # keep the parser's own rows around too, for TXT/Excel export
                rows = []
                if "error" not in result:
                    try:
                        _c, rows = visa_parser.parse_message_full(_prepare_hex_input(raw))
                    except Exception:
                        rows = []
                self.root.after(0, lambda: self._show_result(result, warnings, compact, rows))
            except Exception as e:
                self.root.after(0, lambda: self._show_error(str(e)))

        threading.Thread(target=_worker, daemon=True).start()

    def _show_error(self, msg):
        self.btn_parse.config(state="normal", text="⚡  PARSE MESSAGE")
        self._status(f"🔴  Error: {msg}"); messagebox.showerror("Parse Error", msg)

    def _show_result(self, result, warnings, compact_line, rows):
        self._last_result = result; self._last_warnings = warnings
        self._last_compact = compact_line; self._last_rows = rows
        self.btn_parse.config(state="normal", text="⚡  PARSE MESSAGE")
        if "error" in result:
            self._status(f"🔴  {result['error']}")
            self.output_text.config(state="normal"); self.output_text.delete("1.0", "end")
            self.output_text.insert("end", f"ERROR: {result['error']}\n", "error")
            self.output_text.config(state="disabled"); return

        self.output_text.config(state="normal"); self.output_text.delete("1.0", "end")
        W = 74

        def _put(text, tag=None):
            if tag:
                self.output_text.insert("end", text, tag)
            else:
                self.output_text.insert("end", text)

        _put("═" * W + "\n", "sep")
        _put("  VISANET  ISO 8583  ·  DECODED MESSAGE\n", "header")
        _put("  Authorization-Only Online Messages\n", "note")
        _put("═" * W + "\n", "sep")
        if "MSG_HEADER" in result:
            _put("\n▸ MESSAGE HEADER (H1–H14)\n", "section")
            for k, v in result["MSG_HEADER"].items():
                _put(f"  {k+':':<40} ", "key"); _put(f"{v}\n", "value")
        if "MTI" in result:
            m = result["MTI"]
            _put("\n▸ MTI – Message Type Identifier\n", "section")
            _put(f"  {m.get('Code','')}  ", "mti"); _put(f"{m.get('Description','')}\n", "value")
        if "BITMAP" in result:
            b = result["BITMAP"]
            _put("\n▸ BITMAP\n", "section")
            _put(f"  {'Primary  (hex):':<22} ", "key"); _put(f"{b['Primary (hex)']}\n", "bitmap")
            _put(f"  {'Secondary(hex):':<22} ", "key"); _put(f"{b['Secondary (hex)']}\n", "bitmap")
            _put(f"  {'Fields present:':<22} ", "key"); _put(f"{b['Fields present']}\n", "value")
        if "FIELDS" in result:
            _put("\n▸ DATA ELEMENTS\n", "section")
            for fname, fval in result["FIELDS"].items():
                _put(f"\n  {fname}\n", "field")
                if isinstance(fval, dict):
                    for k, v in fval.items():
                        if v:
                            _put(f"    {k+':':<46} ", "key"); _put(f"{v}\n", "value")
                elif fval:
                    _put(f"    {'Value:':<46} ", "key"); _put(f"{fval}\n", "value")
        if result.get("PARSE_ERRORS"):
            _put("\n▸ PARSE ERRORS\n", "section")
            for k, v in result["PARSE_ERRORS"].items():
                _put(f"  {k}: {v}\n", "error")
        if warnings:
            _put("\n▸ WARNINGS\n", "section")
            for w in warnings:
                _put(f"  {w}\n", "error" if "🔴" in w else "warning")
        _put("\n" + "═" * W + "\n", "sep")
        self.output_text.config(state="disabled"); self.output_text.see("1.0")

        self.compact_text.config(state="normal"); self.compact_text.delete("1.0", "end")
        self.compact_text.insert("1.0", compact_line); self.compact_text.config(state="disabled")

        for item in self.tree.get_children():
            self.tree.delete(item)
        for fname, fval in result.get("FIELDS", {}).items():
            fnum_str = fname.split()[0]; fname_label = " ".join(fname.split()[1:])
            items = [(k, str(v)) for k, v in fval.items() if v] if isinstance(fval, dict) else [("value", str(fval))]
            first = True
            for sub_k, sub_v in items:
                if first:
                    self.tree.insert("", "end", values=(fnum_str, fname_label, sub_k, sub_v)); first = False
                else:
                    self.tree.insert("", "end", values=("", "", sub_k, sub_v))

        self._update_summary(result, warnings)
        self._status(f"✔  Parsed OK — {len(result.get('FIELDS', {}))} fields  ·  {len(warnings)} warning(s)")

    def _update_summary(self, result, warnings):
        fields = result.get("FIELDS", {})
        by_num = _fields_by_num(fields)
        mti_info = result.get("MTI", {})
        mti_code = mti_info.get("Code", "—") if isinstance(mti_info, dict) else str(mti_info)[:4]
        mti_desc = (mti_info.get("Description", "") if isinstance(mti_info, dict) else "")[:24]
        self._sum_mti.config(text=f"{mti_code} {mti_desc}")
        self._sum_proc.config(text=(_first_val(by_num.get(3)) or "—")[:22])
        self._sum_amt.config(text=(_first_val(by_num.get(4)) or "—")[:18])
        self._sum_rrn.config(text=(_first_val(by_num.get(37)) or "—")[:20])
        self._sum_resp.config(text=(_first_val(by_num.get(39)) or "—")[:20])
        self._sum_stan.config(text=(_first_val(by_num.get(11)) or "—")[:14])
        self._sum_pan.config(text=(_first_val(by_num.get(2)) or "—")[:20])
        self._sum_term.config(text=(_first_val(by_num.get(41)) or "—")[:14])
        wc = len(warnings)
        self._sum_warnc.config(text=str(wc), fg=self.ERROR if wc > 0 else self.SUCCESS)

    def _check_result(self):
        if self._last_result is None or "error" in self._last_result:
            messagebox.showwarning("Nothing to save", "Parse a valid message first."); return False
        return True

    def _save_txt(self):
        if self._check_result():
            self._do_save(txt=True, xlsx=False)

    def _save_xlsx(self):
        if not self._check_result():
            return
        if not HAS_OPENPYXL:
            messagebox.showerror("Missing library", "openpyxl is not installed.\nRun: pip install openpyxl"); return
        self._do_save(txt=False, xlsx=True)

    def _save_both(self):
        if self._check_result():
            self._do_save(txt=True, xlsx=True)

    def _do_save(self, txt=True, xlsx=True):
        folder = self._output_folder.get().strip() or os.path.join(os.path.expanduser("~"), "VISA_Output")
        try:
            # Reuse the parser's own naming convention (RRN_or_STAN + MTI)
            mti = self._last_compact.split(":", 1)[0].strip()
            name = visa_parser.get_report_name(self._last_rows, mti) if self._last_rows else \
                f"{_extract_rrn(self._last_result)}_{_extract_mti(self._last_result).lstrip('0') or '0'}"
            sub = os.path.join(folder, name)
            os.makedirs(sub, exist_ok=True)
            saved = []
            raw_hex_for_report = self._last_raw_input.strip()
            if txt:
                p = os.path.join(sub, f"{name}.txt")
                visa_parser.write_txt_report(p, raw_hex_for_report, self._last_compact, self._last_rows)
                saved.append(f"TXT   →  {p}")
            if xlsx:
                p = os.path.join(sub, f"{name}.xlsx")
                visa_parser.write_xlsx_report(p, raw_hex_for_report, self._last_compact, self._last_rows)
                saved.append(f"Excel →  {p}" if HAS_OPENPYXL else "Excel →  skipped (openpyxl unavailable)")
            self._status(f"✔  Saved to {sub}"); messagebox.showinfo("Saved", "\n".join(saved))
        except Exception as e:
            self._status(f"🔴  Save failed: {e}"); messagebox.showerror("Save Error", str(e))


def main():
    root = tk.Tk()
    try:
        from ctypes import windll; windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass
    style = ttk.Style(root); style.theme_use("clam")
    style.configure("Vertical.TScrollbar", background="#1E2E42", troughcolor="#162233", arrowcolor="#5A7A99", bordercolor="#162233", width=10)
    style.configure("Horizontal.TScrollbar", background="#1E2E42", troughcolor="#162233", arrowcolor="#5A7A99", bordercolor="#162233", width=10)
    app = VisaDecoderApp(root); root.mainloop()


if __name__ == "__main__":
    main()
