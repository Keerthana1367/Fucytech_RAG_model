# TARA Knowledge Document: ADAS
**Status**: Finalized Report
**Generated**: ADAS

---

## 1. System Architecture
| Component | Type | Description | Security Props |
| :--- | :--- | :--- | :--- |
| ADAS System | group | No description provided. | Integrity, Confidentiality, Authenticity, Availability |
| ADAS ECU | default | No description provided. | Integrity, Confidentiality, Authenticity, Availability |
| Sensor Fusion Module | default | No description provided. | Integrity, Confidentiality, Availability |
| Lidar Sensor System | default | No description provided. | Integrity, Authenticity, Availability |
| Camera Sensor System | default | No description provided. | Integrity, Authenticity, Availability |
| Radar Sensor System | default | No description provided. | Integrity, Authenticity, Availability |
| Vehicle Network Interface | default | No description provided. | Integrity, Confidentiality, Authenticity, Availability |
| Fusion Output Data | data | No description provided. | Integrity, Confidentiality |
| Control Signals | data | No description provided. | Integrity, Authenticity, Availability |
| System Status | data | No description provided. | Integrity, Confidentiality |


## 2. Damage Assessment
#### Firmware Tampering of ADAS ECU via Debug Port
- **Description**: Loss of Integrity on the ADAS ECU firmware via debug port allows an attacker to modify critical control logic or perception algorithms. This can lead to incorrect object detection, faulty decision-making, and ultimately uncontrolled vehicle behavior, potentially causing severe accidents.
- **Impact Ratings**: Financial Impact: Severe, Safety Impact: Severe, Operational Impact: Severe, Privacy Impact: Negligible
- **Cyber Losses**: Integrity on ADAS ECU


#### Lidar Sensor Unavailable due to CAN Bus Flooding
- **Description**: Denial of Service on the Lidar Sensor System via CAN bus flooding prevents the sensor from providing environmental data to the ADAS system. This loss of critical input data severely degrades the ADAS system's ability to perceive its surroundings, rendering safety features like automatic emergency braking and adaptive cruise control inoperable, and potentially leading to collisions.
- **Impact Ratings**: Financial Impact: Major, Safety Impact: Major, Operational Impact: Major, Privacy Impact: Negligible
- **Cyber Losses**: Availability on Lidar Sensor System


#### Vehicle Network Interface Authenticity Compromised by Spoofing
- **Description**: Spoofing of the Vehicle Network Interface Authenticity allows an attacker to impersonate legitimate network components. This can lead to the ADAS ECU receiving falsified sensor data or control commands, compromising its decision-making process and potentially causing unsafe vehicle maneuvers or system failures.
- **Impact Ratings**: Financial Impact: Major, Safety Impact: Major, Operational Impact: Major, Privacy Impact: Negligible
- **Cyber Losses**: Authenticity on Vehicle Network Interface


#### Sensor Fusion Module Calibration Data Tampering
- **Description**: Tampering with calibration data in the Sensor Fusion Module leads to misinterpretation of sensor inputs, causing inaccurate environmental models. This directly impacts the ADAS system's ability to accurately detect objects, determine distances, and predict trajectories, severely compromising the effectiveness of safety features and increasing the risk of accidents.
- **Impact Ratings**: Financial Impact: Severe, Safety Impact: Severe, Operational Impact: Severe, Privacy Impact: Negligible
- **Cyber Losses**: Integrity on Sensor Fusion Module


#### Extraction of ADAS ECU Neural Network Model Weights
- **Description**: Extraction of proprietary neural network model weights from the ADAS ECU compromises intellectual property and reveals system vulnerabilities. Adversaries can leverage this information to develop sophisticated spoofing attacks or bypass detection mechanisms, potentially leading to the disabling of safety features or the execution of malicious commands that endanger vehicle occupants and other road users.
- **Impact Ratings**: Financial Impact: Severe, Safety Impact: Major, Operational Impact: Major, Privacy Impact: Moderate
- **Cyber Losses**: Confidentiality on ADAS ECU


## 3. Threat Analysis & Attack Vectors
#### TS: ADAS ECU Firmware Compromise
- **ID**: TS001
- **Category**: Tampering
- **Description**: An attacker exploits physical access to the ADAS ECU's debug port to tamper with its firmware, leading to corrupted control logic. This compromise of integrity allows for manipulation of vehicle behavior. Concurrently, an attacker may target the ADAS ECU's confidentiality by extracting sensitive neural network model weights, revealing system vulnerabilities and enabling further exploitation.
- **Asset at Risk**: ADAS ECU (1bc59ea8-3160-4877-a2d6-bcab17e39d42)
- **Cyber Loss**: Integrity


#### TS: Sensor Data Integrity and Availability Attack
- **ID**: TS002
- **Category**: Denial of Service
- **Description**: An attacker initiates a denial-of-service attack by flooding the CAN bus, rendering the Lidar sensor unavailable. Simultaneously, they exploit the vehicle network interface's authenticity by spoofing its messages, leading the ADAS ECU to process falsified sensor data. Furthermore, calibration data within the Sensor Fusion Module is tampered with, ensuring that even if data were available and authentic, it would be misinterpreted, causing critical safety system failures.
- **Asset at Risk**: Lidar Sensor System (067e8e5a-0098-42e9-be1c-9d94e88a38a9)
- **Cyber Loss**: Availability

