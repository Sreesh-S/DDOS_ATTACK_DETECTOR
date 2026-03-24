# Machine Learning Based DoS/DDoS Attack Detection System

## Project Overview
This project is a complete **Intrusion Detection System (IDS)** built with Django. It uses Machine Learning to detect malicious network traffic in real-time.

### Key Features Implemented:
1.  **Machine Learning Pipeline**:
    -   **Algorithm**: Random Forest Classifier.
    -   **Dataset**: Designed for CICIDS2017.
    -   **Preprocessing**: Automated feature extraction and alignment.
    -   *Note: A dummy model is included for immediate demonstration.*
2.  **Backend API**:
    -   **Endpoint**: `/api/predict/`.
    -   **Function**: Accepts traffic data (JSON), predicts attack type, and calculates confidence.
    -   **Mitigation**: Automatically adds malicious IPs to a blocklist (`BlockedIP` table).
3.  **Admin Dashboard**:
    -   **Live Stats**: Total traffic, attack count, and blocked IPs.
    -   **Visuals**: Interactive charts using Chart.js.
    -   **Logs**: Real-time tables showing recent attacks and mitigation actions.

---

## How to Run This Project on Your PC

### Prerequisites
-   **Python 3.10+** installed.
-   **Internet connection** (to install dependencies).

### Step 1: Install Dependencies
Open your terminal/command prompt in the project folder (`DDOS_ATTACK_DETECTOR`) and run:
```bash
pip install -r requirements.txt
```

### Step 2: Initialize Database
Set up the SQLite database and create necessary tables:
```bash
python manage.py makemigrations detection
python manage.py migrate
```

### Step 3: Start the Server
Launch the Django development server:
```bash
python manage.py runserver
```
*Keep this terminal window open.*

### Step 4: Access the Dashboard
Open your web browser and go to:
👉 **[http://127.0.0.1:8000/](http://127.0.0.1:8000/)**

### Step 5: Simulate Traffic (Real-Time)
To see the system in action (detecting attacks and updating charts live), open a **new** terminal window and run:
```bash
python continuous_traffic.py
```
*This script sends a continuous stream of traffic requests to the API. Watch the dashboard update in real-time! Press `Ctrl+C` to stop.*

---

## Project Structure
-   **`manage.py`**: Django's command-line utility.
-   **`detection/`**: The main app.
    -   `models.py`: Database tables (Prediction, BlockedIP).
    -   `views.py`: API logic and ML inference.
    -   `ml/`: Stores the trained model (`model.pkl`) and preprocessing logic.
-   **`dashboard/`**: Handles the frontend HTML/JS.
-   **`train_model.py`**: Script to retrain the model if you have the full dataset.
-   **`prepare_dataset.py`**: Helper to clean raw CSV data.

## API Documentation
**Endpoint**: `http://127.0.0.1:8000/api/predict/`
-   **Method**: `POST`
-   **Header**: `Content-Type: application/json`
-   **Body**: JSON object containing traffic features (e.g., `{"Source IP": "1.2.3.4", "Flow Duration": 1000, ...}`).
