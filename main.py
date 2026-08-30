from __future__ import annotations

import logging
import os
import queue
import subprocess
import sys
import threading
from datetime import datetime
from pathlib import Path
from tkinter import Canvas, filedialog, messagebox

import customtkinter as ctk

BASE_DIR = Path(__file__).resolve().parent
SRC_DIR = BASE_DIR / "src"
sys.path.insert(0, str(SRC_DIR))

from monitor import FolderMonitor  # noqa: E402
from detector import DetectionResult  # noqa: E402

LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)
logging.basicConfig(
    filename=LOG_DIR / "security_events.log",
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

SAFE_BG = "#0b1220"
SAFE_CARD = "#111827"
DANGER_BG = "#240b12"
DANGER_CARD = "#3b0f1a"


class RansomwareProtectionApp(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()
        self.title("RansomShield AI - Ransomware Detection & Protection System")
        self.geometry("1260x820")
        self.minsize(1120, 720)

        self.monitor: FolderMonitor | None = None
        self.selected_folder = ctk.StringVar(value="No folder selected")
        self.status_text = ctk.StringVar(value="Idle")
        self.risk_text = ctk.StringVar(value="SAFE")
        self.score_text = ctk.StringVar(value="0%")
        self.events_text = ctk.StringVar(value="0")
        self.entropy_text = ctk.StringVar(value="0")
        self.ext_text = ctk.StringVar(value="0")
        self.rename_text = ctk.StringVar(value="0")
        self.ai_text = ctk.StringVar(value="AI SAFE")
        self.ai_prob_text = ctk.StringVar(value="0%")
        self.ai_reason_text = ctk.StringVar(value="AI reason: waiting for activity")
        self.alerted_high = False
        self.event_queue: queue.Queue[tuple[str, str, str | None, DetectionResult]] = queue.Queue()
        self.score_history: list[int] = []
        self.ai_history: list[int] = []
        self.main_frame: ctk.CTkFrame | None = None
        self.metric_cards: list[ctk.CTkFrame] = []

        self._build_layout()
        self.after(200, self._drain_events)

    def _build_layout(self) -> None:
        self.grid_columnconfigure(0, weight=0)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        sidebar = ctk.CTkFrame(self, width=300, corner_radius=0)
        sidebar.grid(row=0, column=0, sticky="nsew")
        sidebar.grid_rowconfigure(13, weight=1)

        title = ctk.CTkLabel(sidebar, text="🛡️ RansomShield AI", font=ctk.CTkFont(size=26, weight="bold"))
        title.grid(row=0, column=0, padx=22, pady=(28, 6), sticky="w")
        subtitle = ctk.CTkLabel(sidebar, text="Defensive ransomware behavior monitor", text_color="#9fb3c8")
        subtitle.grid(row=1, column=0, padx=22, pady=(0, 20), sticky="w")

        ctk.CTkButton(sidebar, text="Choose Folder", height=42, command=self.choose_folder).grid(row=2, column=0, padx=22, pady=8, sticky="ew")
        ctk.CTkButton(sidebar, text="Start Monitoring", height=42, fg_color="#198754", hover_color="#157347", command=self.start_monitoring).grid(row=3, column=0, padx=22, pady=8, sticky="ew")
        ctk.CTkButton(sidebar, text="Stop Monitoring", height=42, fg_color="#dc3545", hover_color="#bb2d3b", command=self.stop_monitoring).grid(row=4, column=0, padx=22, pady=8, sticky="ew")
        ctk.CTkButton(sidebar, text="Run Safe Demo", height=42, fg_color="#6f42c1", hover_color="#59359a", command=self.run_demo).grid(row=5, column=0, padx=22, pady=8, sticky="ew")
        ctk.CTkButton(sidebar, text="Open Logs Folder", height=42, command=self.open_logs).grid(row=6, column=0, padx=22, pady=8, sticky="ew")

        info = ctk.CTkFrame(sidebar, fg_color="#111827")
        info.grid(row=7, column=0, padx=22, pady=(22, 8), sticky="ew")
        ctk.CTkLabel(info, text="Selected Folder", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=14, pady=(12, 2))
        ctk.CTkLabel(info, textvariable=self.selected_folder, wraplength=240, text_color="#cbd5e1").pack(anchor="w", padx=14, pady=(0, 14))

        ctk.CTkLabel(sidebar, text="Safety Note", font=ctk.CTkFont(size=14, weight="bold")).grid(row=8, column=0, padx=22, pady=(18, 0), sticky="w")
        ctk.CTkLabel(
            sidebar,
            text="Defensive only. It monitors file activity, predicts risk, and never encrypts, deletes, or attacks files.",
            wraplength=250,
            justify="left",
            text_color="#9fb3c8",
        ).grid(row=9, column=0, padx=22, pady=(4, 10), sticky="w")

        self.main_frame = ctk.CTkFrame(self, corner_radius=0, fg_color=SAFE_BG)
        main = self.main_frame
        main.grid(row=0, column=1, sticky="nsew")
        main.grid_columnconfigure((0, 1, 2, 3), weight=1)
        main.grid_rowconfigure(5, weight=1)

        header = ctk.CTkFrame(main, fg_color="transparent")
        header.grid(row=0, column=0, columnspan=4, padx=28, pady=(24, 8), sticky="ew")
        header.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(header, text="Live Security Dashboard", font=ctk.CTkFont(size=30, weight="bold")).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(header, textvariable=self.status_text, font=ctk.CTkFont(size=16), text_color="#38bdf8").grid(row=0, column=1, sticky="e")

        self.risk_card = self.metric_card(main, "Risk Level", self.risk_text, "Current behavior state", 1, 0)
        self.score_card = self.metric_card(main, "Risk Score", self.score_text, "Rule-based + AI adjusted", 1, 1)
        self.metric_card(main, "Recent Events", self.events_text, "Events in time window", 1, 2)
        self.metric_card(main, "High Entropy", self.entropy_text, "Suspicious file content", 1, 3)
        self.metric_card(main, "Suspicious Ext", self.ext_text, "Encrypted-looking names", 2, 0)
        self.metric_card(main, "Rename Events", self.rename_text, "Mass rename indicator", 2, 1)
        self.metric_card(main, "AI Decision", self.ai_text, "ML confidence label", 2, 2)
        self.metric_card(main, "AI Probability", self.ai_prob_text, "Predicted ransomware risk", 2, 3)

        graph_frame = ctk.CTkFrame(main, fg_color=SAFE_CARD)
        graph_frame.grid(row=3, column=0, columnspan=2, padx=12, pady=12, sticky="nsew")
        ctk.CTkLabel(graph_frame, text="Real-time Risk Graph", font=ctk.CTkFont(size=18, weight="bold")).pack(anchor="w", padx=16, pady=(12, 2))
        self.graph_canvas = Canvas(graph_frame, height=130, bg="#020617", highlightthickness=0)
        self.graph_canvas.pack(fill="both", expand=True, padx=16, pady=(6, 14))

        actions = ctk.CTkFrame(main, fg_color=SAFE_CARD)
        actions.grid(row=3, column=2, columnspan=2, padx=12, pady=12, sticky="nsew")
        ctk.CTkLabel(actions, text="AI Response Panel", font=ctk.CTkFont(size=18, weight="bold")).pack(anchor="w", padx=16, pady=(12, 2))
        ctk.CTkLabel(actions, textvariable=self.ai_reason_text, text_color="#94a3b8", wraplength=430, justify="left").pack(anchor="w", padx=16, pady=(0, 12))
        ctk.CTkButton(actions, text="Simulated Isolate Folder", command=self.simulate_isolation, fg_color="#f59e0b", text_color="#111827").pack(anchor="w", padx=16, pady=(0, 14))

        log_frame = ctk.CTkFrame(main, fg_color=SAFE_CARD)
        log_frame.grid(row=5, column=0, columnspan=4, padx=28, pady=(10, 28), sticky="nsew")
        log_frame.grid_rowconfigure(1, weight=1)
        log_frame.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(log_frame, text="Live Event Log", font=ctk.CTkFont(size=20, weight="bold")).grid(row=0, column=0, padx=16, pady=(14, 8), sticky="w")
        self.log_box = ctk.CTkTextbox(log_frame, fg_color="#020617", text_color="#e5e7eb", corner_radius=12)
        self.log_box.grid(row=1, column=0, padx=16, pady=(0, 16), sticky="nsew")
        self._append_log("Ready. Choose a test folder and start monitoring.")
        self._draw_graph()

    def metric_card(self, parent, title, value_var, caption, row, col):
        card = ctk.CTkFrame(parent, fg_color=SAFE_CARD)
        card.grid(row=row, column=col, padx=12, pady=12, sticky="nsew")
        self.metric_cards.append(card)
        ctk.CTkLabel(card, text=title, text_color="#94a3b8", font=ctk.CTkFont(size=14)).pack(anchor="w", padx=16, pady=(14, 2))
        ctk.CTkLabel(card, textvariable=value_var, font=ctk.CTkFont(size=28, weight="bold")).pack(anchor="w", padx=16, pady=(0, 2))
        ctk.CTkLabel(card, text=caption, text_color="#64748b", font=ctk.CTkFont(size=12)).pack(anchor="w", padx=16, pady=(0, 14))
        return card

    def choose_folder(self) -> None:
        folder = filedialog.askdirectory(title="Choose folder to monitor")
        if folder:
            self.selected_folder.set(folder)
            self._append_log(f"Selected folder: {folder}")

    def start_monitoring(self) -> None:
        folder = self.selected_folder.get()
        if not folder or folder == "No folder selected":
            messagebox.showwarning("Select folder", "Please choose a folder first.")
            return
        self.stop_monitoring(silent=True)
        self.alerted_high = False
        self.score_history.clear()
        self.ai_history.clear()
        self.monitor = FolderMonitor(folder, self._queue_event)
        self.monitor.start()
        self.status_text.set("Monitoring Active")
        self._set_alert_theme(False)
        self._append_log(f"Monitoring started: {folder}")

    def stop_monitoring(self, silent: bool = False) -> None:
        if self.monitor:
            self.monitor.stop()
            self.monitor = None
        self.status_text.set("Idle")
        if not silent:
            self._append_log("Monitoring stopped.")

    def _queue_event(self, event_type: str, path: str, dest: str | None, result: DetectionResult) -> None:
        self.event_queue.put((event_type, path, dest, result))

    def _drain_events(self) -> None:
        while True:
            try:
                event_type, path, dest, result = self.event_queue.get_nowait()
            except queue.Empty:
                break
            self.update_dashboard(result)
            display_path = Path(dest or path).name
            self._append_log(
                f"{event_type.upper():8} | {display_path} | Risk={result.risk_level} "
                f"Score={result.score}% | AI={result.ai_probability}%"
            )
            if result.risk_level == "HIGH" and not self.alerted_high:
                self.alerted_high = True
                self._play_alert_sound()
                messagebox.showwarning(
                    "High Risk Alert",
                    "Ransomware-like behavior detected. The UI turned red and the AI panel shows why.",
                )
        self.after(200, self._drain_events)

    def update_dashboard(self, result: DetectionResult) -> None:
        self.risk_text.set(result.risk_level)
        self.score_text.set(f"{result.score}%")
        self.events_text.set(str(result.event_count_window))
        self.entropy_text.set(str(result.high_entropy_count))
        self.ext_text.set(str(result.suspicious_extension_count))
        self.rename_text.set(str(result.rename_count))
        self.ai_text.set(result.ai_label)
        self.ai_prob_text.set(f"{result.ai_probability}%")
        self.ai_reason_text.set(f"AI reason: {result.ai_explanation}")
        self.score_history.append(result.score)
        self.ai_history.append(result.ai_probability)
        self.score_history = self.score_history[-40:]
        self.ai_history = self.ai_history[-40:]
        self._draw_graph()
        self._set_alert_theme(result.risk_level == "HIGH")

        if result.risk_level == "HIGH":
            self.status_text.set("⚠ High Risk Detected")
        elif result.risk_level == "MEDIUM":
            self.status_text.set("Medium Risk")
        elif self.monitor:
            self.status_text.set("Monitoring Active")

    def _draw_graph(self) -> None:
        self.graph_canvas.delete("all")
        w = max(self.graph_canvas.winfo_width(), 400)
        h = max(self.graph_canvas.winfo_height(), 120)
        self.graph_canvas.create_text(12, 14, anchor="w", fill="#94a3b8", text="Rule score bars + AI probability line")
        self.graph_canvas.create_line(30, h - 25, w - 15, h - 25, fill="#334155")
        values = self.score_history or [0]
        ai_values = self.ai_history or [0]
        step = max((w - 60) / max(len(values), 1), 8)
        for i, value in enumerate(values):
            x = 35 + i * step
            bar_h = int((h - 55) * (value / 100))
            color = "#ef4444" if value >= 70 else "#f59e0b" if value >= 35 else "#22c55e"
            self.graph_canvas.create_rectangle(x, h - 25 - bar_h, x + min(step - 2, 10), h - 25, fill=color, outline="")
        points = []
        for i, value in enumerate(ai_values):
            x = 40 + i * step
            y = h - 25 - int((h - 55) * (value / 100))
            points.extend([x, y])
        if len(points) >= 4:
            self.graph_canvas.create_line(*points, fill="#38bdf8", width=2, smooth=True)

    def _set_alert_theme(self, danger: bool) -> None:
        if self.main_frame:
            self.main_frame.configure(fg_color=DANGER_BG if danger else SAFE_BG)
        for card in self.metric_cards:
            card.configure(fg_color=DANGER_CARD if danger else SAFE_CARD)

    def _play_alert_sound(self) -> None:
        try:
            if sys.platform.startswith("win"):
                import winsound
                winsound.MessageBeep(winsound.MB_ICONHAND)
                winsound.Beep(900, 250)
                winsound.Beep(650, 250)
            else:
                self.bell()
        except Exception:
            self.bell()

    def run_demo(self) -> None:
        folder = self.selected_folder.get()
        if not folder or folder == "No folder selected":
            messagebox.showwarning("Select folder", "Choose a test folder first, then click Run Safe Demo.")
            return
        if not self.monitor:
            self.start_monitoring()
        self._append_log("Running safe demo activity...")

        def worker():
            script = SRC_DIR / "simulator.py"
            subprocess.run([sys.executable, str(script), folder, "--count", "18"], check=False)

        threading.Thread(target=worker, daemon=True).start()

    def simulate_isolation(self) -> None:
        self.stop_monitoring(silent=True)
        self.status_text.set("Folder Isolated (Simulated)")
        self._append_log("Simulated response: monitoring stopped and folder marked as isolated.")
        messagebox.showinfo("Simulated Isolation", "Safe demo response completed. In real systems this could trigger endpoint isolation or backups.")

    def open_logs(self) -> None:
        try:
            if sys.platform.startswith("win"):
                os.startfile(LOG_DIR)  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                subprocess.run(["open", str(LOG_DIR)], check=False)
            else:
                subprocess.run(["xdg-open", str(LOG_DIR)], check=False)
        except Exception:
            messagebox.showinfo("Logs", f"Logs folder: {LOG_DIR}")

    def _append_log(self, message: str) -> None:
        now = datetime.now().strftime("%H:%M:%S")
        self.log_box.insert("end", f"[{now}] {message}\n")
        self.log_box.see("end")
        logging.info(message)

    def on_closing(self) -> None:
        self.stop_monitoring(silent=True)
        self.destroy()


if __name__ == "__main__":
    app = RansomwareProtectionApp()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()
