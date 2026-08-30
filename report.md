# RansomShield AI: Ransomware Detection & Protection System

## 1. Introduction

Ransomware is a type of malware that encrypts or locks files and demands payment. This project is a defensive monitoring tool that detects ransomware-like behavior in a selected folder. It is designed for education and demonstration only.

## 2. Objectives

- Monitor a user-selected folder in real time.
- Detect suspicious activity such as rapid modifications and mass renaming.
- Identify suspicious encrypted-looking extensions like `.locked` and `.encrypted`.
- Calculate file entropy to notice encrypted/compressed-looking content.
- Use a lightweight AI model to estimate ransomware probability.
- Show alerts, logs, graphs, and response recommendations in a GUI.

## 3. System Design

The project has four main components:

### File Monitor

`src/monitor.py` uses the `watchdog` library to observe file-system events such as created, modified, deleted, and moved files.

### Rule-based Detector

`src/detector.py` scores suspicious behavior using defensive rules:

- high number of events in a short time window
- multiple rename events
- suspicious extensions
- high entropy values

### AI Risk Model

`src/ai_model.py` contains a lightweight logistic-style classifier. The AI model receives features from the rule-based detector and predicts a ransomware probability.

The AI inputs are:

- recent event count
- high entropy count
- suspicious extension count
- rename count
- rule-based risk score

The AI outputs are:

- AI label: AI SAFE / AI LOW / AI MEDIUM / AI HIGH
- probability percentage
- explanation of the strongest signals

### GUI Dashboard

`main.py` provides the graphical interface. It shows:

- risk level
- risk score
- AI decision
- AI probability
- recent events
- high entropy count
- suspicious extension count
- rename count
- real-time graph
- event logs
- alert popup and sound alarm

## 4. Safety

The project does not perform harmful operations. It does not encrypt, delete, spread, steal, or attack files. The demo script only creates and renames harmless files inside the selected test folder.

## 5. How the AI Improves the Project

The rule-based detector gives direct points for individual indicators. The AI layer combines several weak signals together. For example, a few suspicious extensions plus many rename events may be more dangerous together than separately. The AI produces a probability score and explanation, making the system more realistic and easier to present.

## 6. Conclusion

RansomShield AI demonstrates behavior-based ransomware detection with a professional GUI and an explainable AI risk layer. It is a safe educational project for Information Security.
