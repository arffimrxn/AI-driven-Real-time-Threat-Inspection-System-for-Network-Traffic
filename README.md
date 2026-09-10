# Machine Learning-based Real-Time Threat Inspection System for Network Traffic

## 1. Project Information

- **Research Title:** Machine Learning-based Real-Time Threat Inspection System for Network Traffic
- **Group Number:** Group P
- **Assigned Research Area:** Cyber Security / Network Traffic Analysis and Machine Learning

### Group Members

- Muhammad Zainul Akhtar Bin Nor Azman – 52215225187
- Ariff Imran Bin Alwi – 52215225001
- Muhammad Firdaus Bin Hairumaini – 52215225004
- Muhammad Isyraf Bin Ismail – 52215124383

---

## 2. Research Problem

Modern enterprise networks face critical challenges during high-volume volumetric attacks such as Distributed Denial-of-Service (DDoS) attacks.

- **Analyst Alert Fatigue & Latency:** Manual parsing of raw `.pcap` files and CSV telemetry logs is labor-intensive, creating severe triage bottlenecks for Security Operations Center (SOC) analysts during active network attacks.
- **Failure of Static Signatures:** Traditional signature-based Intrusion Detection Systems (IDS) may struggle to detect rapidly evolving volumetric attacks without continuous manual rule updates, potentially resulting in false negatives.

---

## 3. Research Aim

To design, develop, and evaluate an automated, machine learning-driven real-time network threat inspection system that ingests network telemetry files, performs network traffic classification, and visualizes actionable threat metrics through a centralized web dashboard.

---

## 4. Research Objectives

- **RO1:** To investigate limitations such as data preparation latency and throughput that may inhibit contemporary AI approaches from consuming live network packet traffic streams.
- **RO2:** To construct a Python-based backend tool using network packet parsing libraries to extract and structure designated network information directly from original PCAP data sources.
- **RO3:** To assess the latency of the extraction tool and the accuracy of the structured data, thereby determining its suitability as an AI data preparation component for real-time network threat inspection.

---

## 5. Brief Description of the Proposed Solution

The proposed solution is a passive, localized web-based threat triage engine designed for Security Operations Centers (SOCs).

Security analysts can upload network traffic files such as `.csv` or `.pcap` through the Django-powered dashboard. The backend automatically processes the network traffic data, cleans the dataset by handling infinity and `NaN` values, and prepares the required features for machine learning inference.

The processed data is then fed into an optimized **Random Forest** machine learning model for threat classification.

The system provides a SOC-style dashboard containing:
- Total packets/flows processed
- Number of threats detected
- Detection/inference latency
- Classification results
- Color-coded network traffic information
- 200-flow triage table

The objective is to reduce the amount of manual effort required to investigate large volumes of network traffic.

---

## 6. Methodology & Development Model

### Research Methodology

**Cross-Industry Standard Process for Data Mining (CRISP-DM)**
The project follows the CRISP-DM methodology:
1. Business Understanding
2. Data Understanding
3. Data Preparation
4. Modelling
5. Evaluation
6. Deployment

### Development Model

**Agile Framework – Iterative and Incremental Model**
The system is developed incrementally, allowing individual components such as data preprocessing, machine learning, backend integration, and dashboard development to be implemented and tested in stages.

---

## 7. Proposed Evaluation Plan

### Baseline for Comparison
A standard **Decision Tree** algorithm is used as the baseline model. The Decision Tree and Random Forest models are evaluated using the same dataset splits and feature vectors to provide a fair comparison.

### Dataset / Test Environment
**Dataset:** CIC-IDS2017

**Primary Dataset:**
```text
Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
```

---

## 8. Proposed System Architecture

The system uses a modular **3-Tier Web Architecture**.

### Presentation Tier — Frontend
**Technologies:** Django HTML Templates, Bootstrap 5, HTML, CSS, JavaScript
**Responsibilities:**
- Network traffic file upload
- SOC dashboard interface
- KPI rendering
- Threat result visualization
- Network traffic triage table

### Application Tier — Backend
**Technologies:** Python, Django, Pandas, NumPy
**Responsibilities:**
- Secure file uploads
- HTTP request handling
- Session management
- Data preprocessing
- Machine learning model integration

### Analytical & Artifact Tier — ML Engine
**Technologies:** Scikit-Learn, Random Forest, Joblib
**Main Artifacts:**
```text
rf_model.joblib
model_metrics.json
```

---

## 9. Description of Technical Components Included in Repository

- `04_Source_Code/train_model.py`: The core machine learning script that ingests the dataset, applies data hygiene, trains the models, and exports the `.joblib` and `.json` artifacts.
- `04_Source_Code/manage.py` & `views.py`: The Django backend files handling routing, HTTP requests, and connecting the ML model to the frontend.
- `04_Source_Code/utils.py`: Contains the automated Pandas pipeline to strip whitespaces, map categorical data, and drop text strings prior to inference.
- `04_Source_Code/detector/templates/detector/dashboard.html`: The HTML frontend interface displaying dynamic metrics via Django template variables.
- `05_Dataset_Inputs/`: Directory housing the benchmark CIC-IDS2017 CSV files.
- `06_Results/Model_Evaluation_Reports.txt`: Statically generated classification reports proving baseline vs. primary model empirical scores.

---

## 10. Technology Stack

| Category | Technology |
|---|---|
| **Programming Languages** | Python 3, HTML, CSS, JavaScript |
| **Web Framework** | Django |
| **Machine Learning** | Scikit-Learn |
| **Data Processing** | Pandas, NumPy |
| **Network / Packet Parsing** | Scapy |
| **Model Serialization** | Joblib |
| **Frontend UI** | Bootstrap 5 |
| **Dataset** | CIC-IDS2017 |
| **Version Control** | Git / GitHub |
| **SIEM** | Wazuh (planned) |

---

## 11. Project Structure

```text
Project/
│
├── 04_Source_Code/
│   ├── train_model.py
│   ├── manage.py
│   ├── views.py
│   ├── utils.py
│   │
│   └── detector/
│       └── templates/
│           └── detector/
│               └── dashboard.html
│
├── 05_Dataset_Inputs/
│   └── CIC-IDS2017/
│
├── 06_Results/
│   └── Model_Evaluation_Reports.txt
│
└── README.md
```

---

## 12. Installation

### Prerequisites
Make sure Python 3 is installed on your system.
Check the Python version:
```bash
python --version
```

### Install Dependencies
Install the required Python libraries:
```bash
pip install django pandas numpy scikit-learn scapy joblib
```

---

## 13. How to Run the Project

### Step 1 — Navigate to the Source Code
Open a terminal and navigate to the source code directory:
```bash
cd 04_Source_Code
```

### Step 2 — Train the Machine Learning Model
Run the training script:
```bash
python train_model.py
```
The script will generate the required machine learning model and performance metric files.

**Expected output:**
- `rf_model.joblib`
- `model_metrics.json`

### Step 3 — Launch the Django Dashboard
After training the model, start the Django development server:
```bash
python manage.py runserver
```
The dashboard will be available at: `http://127.0.0.1:8000/`. Open the address in your web browser to access the SOC dashboard.

### Step 4 — Upload a Dataset
Upload a compatible CIC-IDS2017 CSV file from `05_Dataset_Inputs/`. The system will process the uploaded data and display the machine learning inference results on the dashboard.

---

## 14. Evaluating Different Attack Types

The system can be evaluated using different CIC-IDS2017 attack datasets. By default, the model is trained using the Friday Afternoon DDoS dataset. To evaluate another attack type:

**1. Add the Dataset**
Place the desired CIC-IDS2017 CSV file inside `05_Dataset_Inputs/CIC-IDS2017/`.

**2. Update the Dataset Path**
Open `04_Source_Code/train_model.py`. Locate the `dataset_path` variable and change it to the desired dataset.
*Example:*
```python
dataset_path = "05_Dataset_Inputs/CIC-IDS2017/your_dataset.csv"
```

**3. Retrain the Model**
```bash
cd 04_Source_Code
python train_model.py
```

**4. Restart the Django Server**
```bash
python manage.py runserver
```
The dashboard will then use the newly trained model and updated performance metrics.

---

## 15. Model Evaluation

The primary Random Forest model is compared against a Decision Tree baseline. Both models are evaluated using the same dataset, feature vectors, dataset splits, and evaluation metrics.

### Performance Targets
| Metric | Target |
|---|---|
| **Accuracy** | > 90% |
| **Precision** | > 90% |
| **Recall** | > 90% |
| **F1-Score** | > 90% |
| **Per-packet Inference Latency** | < 5.0 ms |

Detailed results can be found in `06_Results/Model_Evaluation_Reports.txt`.

---

## 16. Future Improvements

Future development may include:
- Real-time network packet capture
- Support for additional CIC-IDS2017 attack types
- Direct PCAP file processing
- Wazuh SIEM integration
- Automated security alert generation
- Real-time packet monitoring
- Improved network feature extraction
- Model optimization for lower inference latency
- Additional machine learning algorithms for comparison

---

## 17. Project Status

**Status:** In Development

The current prototype focuses on automated network traffic preprocessing, machine learning-based threat classification, and visualization through a Django-based Security Operations Center (SOC) dashboard.
