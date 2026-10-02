import tkinter as tk
from collections import Counter
from tkinter import ttk

from scan_ui import ScanApp


class DashboardApp(ScanApp):
    def __init__(self, root):
        super().__init__(root)

        root.title("ZAP Lab Scanner — Dashboard")

        self.loaded_report = None
        self.loaded_path = None

        # Insert the dashboard controls above the alerts table.
        container = self.table.master.master
        panel = ttk.Frame(container)
        panel.pack(
            fill="x",
            pady=(8, 6),
            before=self.table.master,
        )

        self.summary = tk.StringVar(value="No report loaded")

        ttk.Label(
            panel,
            textvariable=self.summary,
            font=("Segoe UI", 10, "bold"),
            wraplength=1000,
        ).pack(anchor="w", pady=(0, 8))

        filters = ttk.Frame(panel)
        filters.pack(fill="x")

        ttk.Label(filters, text="Risk:").pack(side="left")

        self.risk_filter = tk.StringVar(value="All")
        self.risk_box = ttk.Combobox(
            filters,
            textvariable=self.risk_filter,
            values=(
                "All",
                "High",
                "Medium",
                "Low",
                "Informational",
            ),
            state="readonly",
            width=15,
        )
        self.risk_box.pack(side="left", padx=(6, 16))

        ttk.Label(filters, text="Search:").pack(side="left")

        self.search_text = tk.StringVar()
        self.search_entry = ttk.Entry(
            filters,
            textvariable=self.search_text,
        )
        self.search_entry.pack(
            side="left",
            padx=6,
            fill="x",
            expand=True,
        )

        ttk.Button(
            filters,
            text="Clear filters",
            command=self.clear_filters,
        ).pack(side="left", padx=(8, 0))

        self.visible_count = tk.StringVar(value="Showing: 0 / 0")
        ttk.Label(
            panel,
            textvariable=self.visible_count,
        ).pack(anchor="w", pady=(6, 0))

        self.risk_filter.trace_add("write", self.on_filter_change)
        self.search_text.trace_add("write", self.on_filter_change)

    def clear_results(self):
        super().clear_results()

        self.loaded_report = None
        self.loaded_path = None
        self.summary.set("No report loaded")
        self.visible_count.set("Showing: 0 / 0")

    def display_report(self, report, path):
        # Keep the complete report separate from the filtered display.
        self.loaded_report = report
        self.loaded_path = path

        alerts = report["alerts"]
        counts = Counter(
            alert.get("risk", "Unknown") for alert in alerts
        )

        parts = [
            f"Total: {len(alerts)}",
            f"High: {counts['High']}",
            f"Medium: {counts['Medium']}",
            f"Low: {counts['Low']}",
            f"Informational: {counts['Informational']}",
        ]

        other_count = sum(
            count
            for risk, count in counts.items()
            if risk not in (
                "High",
                "Medium",
                "Low",
                "Informational",
            )
        )

        if other_count:
            parts.append(f"Other: {other_count}")

        self.summary.set("   |   ".join(parts))
        self.apply_filters()

        # Return the total, not the number of visible rows.
        return len(alerts)

    def on_filter_change(self, *args):
        self.apply_filters()

    def clear_filters(self):
        self.risk_filter.set("All")
        self.search_text.set("")

    def apply_filters(self):
        if self.loaded_report is None:
            return

        risk = self.risk_filter.get()
        query = self.search_text.get().strip().casefold()
        matching = []

        for alert in self.loaded_report["alerts"]:
            if risk != "All" and alert.get("risk") != risk:
                continue

            searchable_text = " ".join(
                str(alert.get(field, ""))
                for field in ("alert", "url", "param")
            ).casefold()

            if query and query not in searchable_text:
                continue

            matching.append(alert)

        # Create a display-only copy. The original report is unchanged.
        filtered_report = {
            **self.loaded_report,
            "alerts": matching,
        }

        super().display_report(
            filtered_report,
            self.loaded_path,
        )

        total = len(self.loaded_report["alerts"])
        self.visible_count.set(
            f"Showing: {len(matching)} / {total}"
        )


if __name__ == "__main__":
    root = tk.Tk()
    app = DashboardApp(root)
    root.mainloop()