# 🛡️ DDoS Attack Detector - Deployment Instructions

Follow these steps to set up and run the project on a Windows PC.

## 1️⃣ Prerequisites & Installations
Ensure the following software and packages are installed:
1. **Python 3.10+**: Run `python --version` to verify.
2. **Npcap**: Required for real-time packet sniffing. 
   - Download and install from [https://nmap.org/npcap/](https://nmap.org/npcap/).
   - **Important**: During installation, check the box for "**Install Npcap in WinPcap API-compatible Mode**".
3. **Wireshark** (Optional): Useful for deep packet inspection and network analysis alongside the project.
4. **Scapy**: Installed via Python packages below to process network packets.

## 2️⃣ Extract & Setup
1. **Unzip** the project file to a desired location (e.g., `C:\Projects\DDOS_DETECTOR`).
2. Open **Command Prompt (cmd)** or **PowerShell** and navigate to the project folder:
   ```powershell
   cd path\to\extracted\folder
   ```
3. **Create a Virtual Environment** (Recommended):
   ```powershell
   python -m venv venv
   ```
4. **Activate the Virtual Environment**:
   ```powershell
   .\venv\Scripts\activate
   ```
   *(You should see `(venv)` at the start of your command line)*
5. **Install Dependencies**:
   ```powershell
   pip install -r requirements.txt
   ```

## 3️⃣ Database & Model Setup
1. **Initialize the Database**:
   ```powershell
   python manage.py makemigrations detection
   python manage.py migrate
   ```
2. **Dataset & Model Setup**:
   If the `model.pkl` is missing:
   ```powershell
   python prepare_dataset.py
   python train_model.py
   ```

## 4️⃣ Running the Project
1. **Start the Django Server**:
   ```powershell
   python manage.py runserver
   ```
   *(Keep this terminal window open)*
2. Open your web browser and go to the **Dashboard**:
   👉 **http://127.0.0.1:8000/**

## 5️⃣ Analyzing Real-Time Traffic
To analyze live packets flowing through your network interfaces:
1. Keep the Django server running in the background.
2. Open a **new** Command Prompt or PowerShell, but run it as **Administrator**.
3. Activate the virtual environment (`.\venv\Scripts\activate`).
4. **Run the Real-Time Sniffer**:
   ```powershell
   python realtime_sniffer.py
   ```
   *(This will listen on your network interfaces, analyze traffic patterns in real-time using Scapy, and report predictions directly to the running Django server. Requires Npcap to be installed).*

## 6️⃣ Simulating the Attack Server
To verify the system is working and detecting attacks without actual malware or live network attacks, use the built-in traffic simulator.
1. Make sure your Django server is running.
2. Open a **new** terminal window and activate the `venv`.
3. **Run the Real-Time Traffic Simulator**:
   ```powershell
   python simulate_realtime_traffic.py
   ```
4. Observe the terminal output. You should see normal traffic mixed with randomly selected DDoS payloads being sent to the AI model.
5. Check the **Dashboard** (http://127.0.0.1:8000/) to see the real-time detection alerts, dynamic updates to graphs, and a live log of blocked IPs!

## 7️⃣ Troubleshooting
* **"WinPcap is not installed"**: Make sure you installed Npcap with WinPcap API compatibility mode enabled.
* **"Failed to connect to Django API"**: Make sure `python manage.py runserver` is actively running.
* **"Model not found"**: Run `python train_model.py` to regenerate the ML model.
