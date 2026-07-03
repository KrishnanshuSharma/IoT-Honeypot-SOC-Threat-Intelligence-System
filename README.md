# Autonomous AI-Driven IoT Honeypot SOC & Automated Mitigation Platform

An enterprise-grade, low-interaction hybrid IoT Deception platform natively engineered for Linux environments. The system orchestrates custom network listeners simulating vulnerable edge infrastructure, leverages a Machine Learning pipeline to profile adversary behaviors, integrates real-time global threat intelligence, and executes autonomous mitigation policies directly at the Linux kernel level via the `netfilter` (`iptables`) framework.

---

## 🚀 Core Engineering Features & System Architecture

The platform operates on a decoupled **Capture ➔ Analyze ➔ Act** architecture, ensuring low footprint, security isolation, and strict Operational Security (OpSec) against anti-honeypot reconnaissance.

* **Multi-Protocol Deception Array:** Custom, highly optimized low-interaction listeners engineered in Python to harvest and log plaintext interactions across modern and legacy IoT vectors:
  * **SSH (Port 22)** & **Telnet (Port 23):** Plaintext credential harvesting engines tracking automated credential stuffing strings.
  * **HTTP (Port 80):** Fake web interface deploying an authentic-looking IoT device administration dashboard login page to intercept web exploitation attempts.
  * **MQTT (Port 1883):** Mimics an open, unauthenticated message broker capturing subscription anomalies and message flood behaviors.
  * **CoAP (Port 5683 over UDP):** High-velocity UDP socket designed to ingest reflection and amplification vectors common in contemporary IoT botnets.
* **AI/ML Ingestion & Classification Pipeline:** Integrated an ensemble **Random Forest Classifier** trained on over 1,500 highly diverse IoT threat signatures. The model achieves **84.83% classification accuracy**, prioritizing robust generalization across minority classes while deliberately avoiding over-parameterized deep learning architectures that degrade edge node computing resources.
* **Hardware-Level Deception (Anti-VM/Anti-Reconnaissance):** To bypass advanced adversaries employing specialized scanner scripts, the host machine implements **MAC Address OUI spoofing (simulating Cisco systems)** and custom service banner masking. Aggressive fingerprinting scans (`nmap -A`) are deliberately fed deceptive parameters, misdirecting attackers into profiling the asset as an enterprise physical router.
* **Real-Time Threat Enrichment:** Dynamic backend integration with the **AbuseIPDB API**, allowing instantaneous lookup of target indicators of compromise (IoCs), live calculation of attacker confidence scores, and geolocational sorting.
* **Autonomous Kernel-Level Mitigation:** Programmatic execution of native Linux firewall controls. Upon identifying high-confidence malicious profiles via the ML engine, the backend automatically generates and injects ephemeral `iptables -A INPUT -s <Attacker_IP> -j DROP` rules to completely isolate the threat actor dynamically.
* **Decoupled Fallback Logic:** Sensor logging and inline kernel mitigation loops are completely isolated from the web presentation interface. In the event of API rate-limiting or internet network degradation, the core honeypot array continues processing and dropping threat traffic autonomously.

---

## 🛠️ Technical Stack & Engineering Assets

* **Languages:** Python 3.9+, HTML5/CSS3, JavaScript (Asynchronous AJAX Ingestion)
* **Frameworks & UI:** Flask Micro-framework, Bootstrap 5 UI Dashboard
* **Data Science & ML:** Scikit-learn, Pandas, NumPy, Joblib (Model Serialization)
* **Security & System Frameworks:** Netfilter/iptables, Core Linux Sockets, Advanced Networking Utilities
* **Testing Tooling:** Nmap (Advanced Scripting Engine), Hydra Network Brute-forcer, Curl

---

## 📁 Repository Blueprint

```text
├── dashboard.py             # Core Flask application orchestration, routing, and AbuseIPDB integration
├── data_preprocessor.py     # Feature engineering, standardization, and text tokenization module
├── train_ai.py              # ML training script, evaluation metrics loop, and model serialization
├── rf_model.pkl             # Serialized production-ready Random Forest model weights
├── master_controller.py     # Parent automation controller supervising sensors and log collectors
├── sensors/
│   ├── http_sensor.py       # Port 80 listener serving the fake router/IoT login interface
│   ├── sensors.py           # Multi-threaded handler bundling SSH, Telnet, and MQTT sockets
└── templates/
    └── index.html           # Live SOC monitoring interface utilizing real-time log ingestion
