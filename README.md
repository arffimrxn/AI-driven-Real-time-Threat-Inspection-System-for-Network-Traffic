# Machine Learning-based Real-Time Threat Inspection System for Network Traffic

## Project Overview
This repository contains a Python-based backend framework designed to extract and structure specific domain-based Indicators of Compromise (IoCs) from raw Wireshark PCAP files. The tool automates the **Data Preparation** phase of the CRISP-DM methodology, bridging the gap between unstructured network telemetry and low-latency AI detection pipelines.

## Group P Members
* Muhammad Zainul Akhtar Bin Nor Azman
* Ariff Imran Bin Alwi
* Muhammad Firdaus Bin Hairumaini
* Muhammad Isyraf Bin Ismail

## Key Features
* **PCAP Parsing:** Ingests live, noisy network traffic streams directly from Wireshark PCAP files.
* **IoC Extraction:** Filters and extracts specific DNS and HTTP domain requests using packet dissection libraries.
* **AI-Ready Structuring:** Formats the extracted data to eliminate latency bottlenecks, enabling immediate ingestion into real-time AI threat intelligence models.

## Technology Stack
* **Language:** Python 3
* **Libraries:** PyShark / Scapy, Pandas (for data structuring)

## Implementation Scope
Targeted for Security Operations Centre (SOC) analysts and data scientists requiring structured network data for AI model training and real-time threat hunting.
