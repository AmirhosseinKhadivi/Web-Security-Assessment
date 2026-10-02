import json
import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from scan_lab import TARGET_URL, run_scan, validate_target


RISK_ORDER = {
    "High": 0,
    "Medium": 1,
    "Low": 2,
    "Informational": 3,
}


class ScanApp:
    def __init__(self, root):
        self.root = root
        self.events = queue.Queue()
        self.running = False
        self.alerts_by_item = {}

        root.title("ZAP Lab Scanner")
        root.geometry("1100x750")
        root.minsize(850, 600)
        root.protocol("WM_DELETE_WINDOW", self.close)

        container = ttk.Frame(root, padding=16)
        container.pack(fill="both", expand=True)

        ttk.Label(
            container,
            text="ZAP Lab Scanner",
            font=("Segoe UI", 18, "bold"),
        ).pack(anchor="w", pady=(0, 12))

        target_row = ttk.Frame(container)
        target_row.pack(fill="x", pady=(0, 8))

        ttk.Label(target_row, text="Local lab URL:").pack(side="left")

        self.target_entry = ttk.Entry(target_row)
        self.target_entry.insert(0, TARGET_URL)
        self.target_entry.pack(
            side="left", padx=8, fill="x", expand=True
        )

        self.paste_url_button = ttk.Button(
            target_row,
            text="Paste URL",
            command=lambda: self.paste_into(self.target_entry),
        )
        self.paste_url_button.pack(side="left")

        controls = ttk.Frame(container)
        controls.pack(fill="x")

        ttk.Label(controls, text="ZAP API key:").pack(side="left")

        self.key_entry = ttk.Entry(controls, show="*", width=35)
        self.key_entry.pack(
            side="left", padx=8, fill="x", expand=True
        )

        self.paste_key_button = ttk.Button(
            controls,
            text="Paste key",
            command=lambda: self.paste_into(self.key_entry),
        )
        self.paste_key_button.pack(side="left", padx=(0, 8))

        self.start_button = ttk.Button(
            controls, text="Start scan", command=self.start_scan
        )
        self.start_button.pack(side="left", padx=(0, 8))

        self.open_button = ttk.Button(
            controls, text="Open report", command=self.open_report
        )
        self.open_button.pack(side="left")

        self.status = tk.StringVar(value="Ready")
        ttk.Label(
            container, textvariable=self.status, wraplength=1000
        ).pack(anchor="w", pady=(12, 4))

        self.progress = ttk.Progressbar(
            container, mode="indeterminate"
        )
        self.progress.pack(fill="x", pady=(0, 12))

        ttk.Label(container, text="Scan messages").pack(anchor="w")

        log_frame = ttk.Frame(container)
        log_frame.pack(fill="both", expand=True, pady=(4, 12))

        self.log = tk.Text(
            log_frame, height=9, state="disabled", wrap="word"
        )
        log_scroll = ttk.Scrollbar(
            log_frame, orient="vertical", command=self.log.yview
        )
        self.log.configure(yscrollcommand=log_scroll.set)
        log_scroll.pack(side="right", fill="y")
        self.log.pack(side="left", fill="both", expand=True)

        ttk.Label(
            container,
            text="Alerts — double-click a row to view details",
        ).pack(anchor="w")

        table_frame = ttk.Frame(container)
        table_frame.pack(fill="both", expand=True, pady=4)
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

        self.table = ttk.Treeview(
            table_frame,
            columns=("risk", "alert", "url"),
            show="headings",
            selectmode="browse",
            height=10,
        )

        for column, title, width in (
            ("risk", "Risk", 100),
            ("alert", "Alert", 470),
            ("url", "URL", 650),
        ):
            self.table.heading(column, text=title)
            self.table.column(column, width=width, stretch=False)

        vertical = ttk.Scrollbar(
            table_frame, orient="vertical", command=self.table.yview
        )
        horizontal = ttk.Scrollbar(
            table_frame, orient="horizontal", command=self.table.xview
        )
        self.table.configure(
            yscrollcommand=vertical.set,
            xscrollcommand=horizontal.set,
        )

        self.table.grid(row=0, column=0, sticky="nsew")
        vertical.grid(row=0, column=1, sticky="ns")
        horizontal.grid(row=1, column=0, sticky="ew")

        self.table.tag_configure("High", foreground="#b91c1c")
        self.table.tag_configure("Medium", foreground="#92400e")
        self.table.bind("<Double-1>", self.on_double_click)
        self.table.bind("<Return>", self.on_enter)

        self.report_path = tk.StringVar()
        ttk.Entry(
            container, textvariable=self.report_path, state="readonly"
        ).pack(fill="x", pady=(8, 0))

        self.key_entry.focus_set()
        root.after(100, self.process_events)

    def paste_into(self, entry):
        if self.running:
            return
        try:
            value = self.root.clipboard_get().strip()
        except tk.TclError:
            messagebox.showwarning("Clipboard", "Copy some text first.")
            return
        entry.delete(0, "end")
        entry.insert(0, value)
        entry.focus_set()

    def append_message(self, message):
        self.log.configure(state="normal")
        self.log.insert("end", str(message) + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def clear_results(self):
        self.report_path.set("")
        self.alerts_by_item.clear()
        for item in self.table.get_children():
            self.table.delete(item)
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")

    def display_report(self, report, path):
        for item in self.table.get_children():
            self.table.delete(item)
        self.alerts_by_item.clear()

        alerts = sorted(
            report["alerts"],
            key=lambda alert: RISK_ORDER.get(alert.get("risk", ""), 99),
        )

        for alert in alerts:
            risk = alert.get("risk", "")
            item = self.table.insert(
                "",
                "end",
                values=(
                    risk,
                    alert.get("alert", ""),
                    alert.get("url", ""),
                ),
                tags=(risk,),
            )
            self.alerts_by_item[item] = alert

        self.report_path.set(str(path))
        return len(alerts)

    def on_double_click(self, event):
        item = self.table.identify_row(event.y)
        if item:
            self.show_details(item)

    def on_enter(self, event):
        selected = self.table.selection()
        if selected:
            self.show_details(selected[0])
        return "break"

    def show_details(self, item):
        alert = self.alerts_by_item.get(item)
        if alert is None:
            return

        window = tk.Toplevel(self.root)
        window.title("Alert details")
        window.geometry("850x650")
        window.minsize(600, 400)
        window.transient(self.root)

        frame = ttk.Frame(window, padding=12)
        frame.pack(fill="both", expand=True)

        text = tk.Text(frame, wrap="word", padx=10, pady=10)
        scroll = ttk.Scrollbar(
            frame, orient="vertical", command=text.yview
        )
        text.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        text.pack(side="left", fill="both", expand=True)
        text.tag_configure("heading", font=("Segoe UI", 11, "bold"))

        fields = (
            ("Alert", "alert"),
            ("Risk", "risk"),
            ("Confidence", "confidence"),
            ("URL", "url"),
            ("HTTP method", "method"),
            ("Parameter", "param"),
            ("Attack payload", "attack"),
            ("Evidence", "evidence"),
            ("Description", "description"),
            ("Solution", "solution"),
            ("Other information", "other"),
            ("References", "reference"),
            ("CWE ID", "cweid"),
            ("Plugin ID", "pluginId"),
        )

        for label, key in fields:
            value = alert.get(key)
            if value is None or value == "":
                value = "(Not provided)"
            text.insert("end", label + "\n", "heading")
            text.insert("end", str(value) + "\n\n")

        text.configure(state="disabled")
        ttk.Button(
            window, text="Close", command=window.destroy
        ).pack(pady=(0, 12))

    def open_report(self):
        if self.running:
            return

        path = filedialog.askopenfilename(
            title="Open a report created by scan_lab.py",
            filetypes=[("JSON reports", "*.json")],
        )
        if not path:
            return

        try:
            with open(path, encoding="utf-8") as file:
                report = json.load(file)

            if not isinstance(report, dict):
                raise ValueError("The report must be a JSON object.")
            if not isinstance(report.get("alerts"), list):
                raise ValueError("The report must contain an alerts list.")

            for alert in report["alerts"]:
                if not isinstance(alert, dict):
                    raise ValueError("Each alert must be a JSON object.")
                for key in ("risk", "alert", "url"):
                    if key in alert and not isinstance(alert[key], str):
                        raise ValueError(f"Alert field '{key}' must be text.")

        except (OSError, ValueError) as exc:
            messagebox.showerror("Cannot open report", str(exc))
            return

        self.clear_results()
        count = self.display_report(report, path)
        target = report.get("target", "(Not provided)")
        self.status.set(f"Report loaded — {count} alerts — {target}")
        self.append_message(f"Loaded report: {path}")
        self.append_message(f"Report target: {target}")
        self.append_message("No new scan was started.")

    def set_running(self, running):
        self.running = running
        state = "disabled" if running else "normal"

        for widget in (
            self.target_entry,
            self.key_entry,
            self.paste_url_button,
            self.paste_key_button,
            self.start_button,
            self.open_button,
        ):
            widget.configure(state=state)

        if running:
            self.progress.start(12)
        else:
            self.progress.stop()
            self.progress["value"] = 0

    def start_scan(self):
        if self.running:
            return

        try:
            target = validate_target(self.target_entry.get())
        except ValueError as exc:
            messagebox.showwarning("Invalid target", str(exc))
            return

        api_key = self.key_entry.get().strip()
        if not api_key:
            messagebox.showwarning(
                "Missing key", "Enter the ZAP API key first."
            )
            return

        self.target_entry.delete(0, "end")
        self.target_entry.insert(0, target)
        self.clear_results()
        self.set_running(True)
        self.status.set(f"Scanning: {target}")

        threading.Thread(
            target=self.scan_worker,
            args=(api_key, target),
            daemon=True,
        ).start()

    def scan_worker(self, api_key, target):
        try:
            report, path = run_scan(
                api_key,
                target_url=target,
                on_message=lambda message: self.events.put(
                    ("message", message)
                ),
            )
            self.events.put(("done", (report, path)))
        except Exception as exc:
            self.events.put(("error", str(exc)))

    def process_events(self):
        try:
            while True:
                event, payload = self.events.get_nowait()

                if event == "message":
                    self.append_message(payload)
                elif event == "done":
                    report, path = payload
                    count = self.display_report(report, path)
                    self.set_running(False)
                    self.status.set(
                        f"Completed — {count} alerts — {report['target']}"
                    )
                elif event == "error":
                    self.append_message(f"ERROR: {payload}")
                    self.set_running(False)
                    self.status.set("Scan failed — see messages")
                    messagebox.showerror("Scan failed", payload)

        except queue.Empty:
            pass

        self.root.after(100, self.process_events)

    def close(self):
        if self.running:
            messagebox.showinfo(
                "Scan in progress",
                "Wait for the scan to finish before closing.",
            )
            return
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = ScanApp(root)
    root.mainloop()