
# 🛡️ RansomGuard-AI: Ransomware Protection System

An advanced, AI-driven cybersecurity tool designed for real-time file monitoring, ransomware behavior detection, and threat simulation[cite: 2]. Built with Python, `watchdog`, and a modern `CustomTkinter` desktop interface[cite: 2].

---

## 🚀 Key Features
- **Real-Time File Monitoring:** Continuously monitors designated directories for suspicious file modifications or rapid encryption patterns using `watchdog`[cite: 2].
- **AI-Powered Detection:** Integrates machine learning logic to analyze threat behaviors and flag potential ransomware activities[cite: 2].
- **Attack Simulation Tool:** Includes a built-in simulator module to safely test detection responses[cite: 2].
- **Modern Desktop UI:** Built using `customtkinter` for a sleek, dark-themed user experience[cite: 2].
- **Cross-Platform Support:** Comes with automated startup scripts for both Windows and Linux/macOS[cite: 2].

---

## 🛠️ Tech Stack
- **Python** 🐍
- **CustomTkinter** (GUI)[cite: 2]
- **Watchdog** (Filesystem events)[cite: 2]
- **Scikit-Learn / AI Model Components**[cite: 2]

---

## 📂 Project Structure
```text
📦 RansomGuard-AI
 ┣ 📂 assets/              # UI assets and icons
 ┣ 📂 logs/                # System activity and detection logs
 ┣ 📂 src/                 # Core source code modules
 ┃  ┣ 📜 ai_model.py       # Machine learning detection logic[cite: 2]
 ┃  ┣ 📜 detector.py       # Threat detection engine[cite: 2]
 ┃  ┣ 📜 monitor.py        # Real-time filesystem monitor[cite: 2]
 ┃  ┗ 📜 simulator.py      # Attack simulation module[cite: 2]
 ┣ 📜 main.py              # Main application entry point[cite: 2]
 ┣ 📜 run.py               # Runner script[cite: 2]
 ┣ 📜 requirements.txt     # Python dependencies[cite: 2]
 ┣ 📜 start_windows.bat    # Windows quick-start script[cite: 2]
 ┗ 📜 start_linux_mac.sh   # Linux/macOS quick-start script[cite: 2]
⚙️ Installation & Running
Clone the repository:

Bash
git clone [https://github.com/rawanosama14/RansomGuard-AI.git](https://github.com/rawanosama14/RansomGuard-AI.git)
cd RansomGuard-AI
Install the dependencies:

Bash
pip install -r requirements.txt
Run the application:

On Windows: Double-click start_windows.bat or run:

Bash
python run.py
On Linux / macOS:

Bash
chmod +x start_linux_mac.sh
./start_linux_mac.sh
