# TARA Knowledge Document: Anti lock breaking system
**Status**: Finalized Report
**Generated**: Anti lock breaking system

---

## 1. System Architecture
| Component | Type | Description | Security Props |
| :--- | :--- | :--- | :--- |
| Anti lock braking system | group | No description provided. | Integrity, Confidentiality, Authenticity, Authorization, Availability |
| ABS ECU | group | No description provided. | Integrity, Confidentiality, Authenticity, Availability |
| ABS MCU | default | No description provided. | Integrity, Availability, Authenticity |
| Firmware (Flash Memory) | default | No description provided. | Integrity, Confidentiality, Authenticity, Availability |
| Hydraulic Control Unit | default | No description provided. | Integrity, Availability |
| Wheel Speed Sensors | default | No description provided. | Integrity, Authenticity |
| OBD-II Interface | default | No description provided. | Authorization, Availability |
| Vehicle CAN | data | No description provided. | Integrity, Authenticity, Availability |
| Cryptographic Keys | default | No description provided. | Confidentiality, Integrity |


## 2. Damage Assessment
#### ABS Firmware Tampering Leading to Critical Safety Function Loss
- **Description**: Loss of firmware integrity on the ABS MCU's flash memory allows an attacker to inject malicious code. This compromised firmware can disable critical ABS safety functions, leading to a severe degradation in braking performance. Such an incident would directly jeopardize vehicle safety, potentially causing accidents with fatal consequences.
- **Impact Ratings**: Financial Impact: Severe, Safety Impact: Severe, Operational Impact: Severe, Privacy Impact: Negligible
- **Cyber Losses**: Integrity on Firmware (Flash Memory)


#### Spoofed Wheel Speed Signal Injection Compromising Braking Performance
- **Description**: An attacker injecting falsified wheel speed signals into the CAN bus can deceive the ABS MCU. The system may interpret normal braking as wheel lock, causing inappropriate actuation of the hydraulic control unit. This leads to reduced braking efficiency and extended stopping distances, significantly increasing the risk of severe accidents and potentially fatalities.
- **Impact Ratings**: Financial Impact: Major, Safety Impact: Major, Operational Impact: Major, Privacy Impact: Negligible
- **Cyber Losses**: Authenticity on Wheel Speed Sensors


#### Denial of Service on ABS MCU Leading to System Unavailability
- **Description**: A denial-of-service attack on the ABS MCU can render the entire ABS system inoperable. This prevents the MCU from processing sensor data or controlling the hydraulic unit, leading to a complete loss of ABS functionality. Such a failure severely impacts vehicle stability and braking control, drastically increasing accident risk.
- **Impact Ratings**: Financial Impact: Major, Safety Impact: Major, Operational Impact: Major, Privacy Impact: Negligible
- **Cyber Losses**: Availability on ABS MCU


#### Cryptographic Key Extraction Enabling System Compromise
- **Description**: Extraction of cryptographic keys via debug interfaces compromises the security of the ABS ECU. These keys are essential for authentication and secure communication. Their compromise enables unauthorized firmware modifications and bypasses of security mechanisms, leading to a cascading failure of system integrity and availability, with significant safety implications.
- **Impact Ratings**: Financial Impact: Severe, Safety Impact: Severe, Operational Impact: Severe, Privacy Impact: Negligible
- **Cyber Losses**: Confidentiality on Cryptographic Keys


#### CAN Bus Message Replay/Modification Compromising Braking System Integrity
- **Description**: Replaying or modifying CAN bus messages related to ABS operation can cause the ABS MCU to make erroneous decisions. This could result in incorrect braking interventions or failure to activate ABS when needed, directly compromising the integrity of the braking system. Such failures significantly increase the risk of accidents.
- **Impact Ratings**: Financial Impact: Major, Safety Impact: Major, Operational Impact: Major, Privacy Impact: Negligible
- **Cyber Losses**: Integrity on Vehicle CAN


## 3. Threat Analysis & Attack Vectors
#### TS: ABS Firmware Tampering via OBD-II/UDS
- **ID**: TS001
- **Category**: Tampering
- **Description**: An attacker with unauthorized access to the OBD-II interface exploits UDS commands (e.g., 0x34/0x36) to flash malicious firmware onto the ABS MCU's flash memory. This compromise leads to the disabling of critical safety functions and a severe degradation of braking performance, resulting in a significant safety risk.
- **Asset at Risk**: Firmware (Flash Memory) (1952e898-54a9-4b6c-8036-55671b0bce63)
- **Cyber Loss**: Integrity

**Attack Tree Summary:**
  - **Primary Goal**: ABS Firmware Tampering Leading to Critical Safety Function Loss
    - **Vector**: Unauthorized access to ABS ECU firmware update interface
      - **Method**: Exploit diagnostic port vulnerabilities (e.g., UDS DoIP, K-Line) to gain privileged access for firmware flashing.
      - **Method**: Compromise Over-the-Air (OTA) update mechanism by intercepting or spoofing update server communication to push malicious firmware to the ABS ECU.
      - **Method**: Physical access to the vehicle's OBD-II port and using specialized tools to bypass authentication and upload modified firmware to the ABS control module.
    - **Vector**: Reverse engineering and modification of existing ABS firmware
      - **Method**: Obtain legitimate ABS firmware image through methods like firmware dumping from a compromised ECU or acquiring leaked manufacturer firmware, then analyze with disassemblers (e.g., IDA Pro, Ghidra) to identify critical safety function logic (e.g., wheel speed sensor processing, valve actuation control).
      - **Method**: Identify and modify specific code sections responsible for ABS activation logic, deceleration thresholds, or brake pressure modulation within the reversed firmware binary.
      - **Method**: Re-compile the modified firmware with altered parameters to disable ABS functionality, introduce incorrect braking behavior, or cause unintended wheel lock-up during braking events.
    - **Vector**: Exploiting vulnerabilities in the ABS ECU's bootloader or flash memory controller
      - **Method**: Identify and exploit buffer overflow or format string vulnerabilities in the bootloader to gain code execution and overwrite the main firmware partition with malicious code.
      - **Method**: Utilize timing-based side-channel attacks or voltage glitching during the firmware flashing process to corrupt the firmware image or bypass write protection mechanisms on the flash memory.
      - **Method**: Leverage known or discovered flaws in the flash memory controller's error correction code (ECC) or wear leveling algorithms to inject corrupted data that alters critical firmware functions.


#### TS: CAN Bus Injection and Manipulation Attack
- **ID**: TS002
- **Category**: Tampering
- **Description**: An attacker gains access to the vehicle's CAN bus to inject spoofed wheel speed signals, misleading the ABS MCU into erroneous braking actions. This can also involve replaying or modifying legitimate CAN messages, compromising the integrity of braking system commands and significantly increasing accident risk.
- **Asset at Risk**: Wheel Speed Sensors (4acd5f0e-37cf-4805-9601-6a0a0abb95a8)
- **Cyber Loss**: Integrity

**Attack Tree Summary:**
  - **Primary Goal**: Spoofed Wheel Speed Signal Injection Compromising Braking Performance
    - **Vector**: Inject malicious signals into the ABS wheel speed sensor network
      - **Method**: Intercept and replay legitimate wheel speed sensor signals with manipulated values
      - **Method**: Generate and inject fabricated wheel speed sensor signals directly into the CAN bus
      - **Method**: Physically manipulate the physical wheel speed sensor output (e.g., by introducing interference or altering magnetic field)
    - **Vector**: Exploit vulnerabilities in the ABS control module to accept spoofed signals
      - **Method**: Gain unauthorized access to the ABS control module's memory and alter firmware logic to bypass signal validation checks
      - **Method**: Leverage buffer overflow or injection vulnerabilities in the ABS control module's input processing to inject arbitrary data interpreted as valid wheel speed
      - **Method**: Utilize diagnostic communication interfaces (e.g., UDS over CAN) to send spoofed wheel speed data commands to the ABS control module
    - **Vector**: Compromise the integrity of the wheel speed sensor's physical or electrical interface
      - **Method**: Introduce electromagnetic interference (EMI) near the wheel speed sensor and its cabling to corrupt legitimate signals
      - **Method**: Temporarily disconnect and reconnect the wheel speed sensor to simulate a sensor failure and potentially inject a default or manipulated value upon reconnection
      - **Method**: Physically access the wheel speed sensor connector and introduce a custom device that feeds fabricated speed data


#### TS: ABS ECU DoS and Key Extraction Attack
- **ID**: TS003
- **Category**: Tampering
- **Description**: A denial-of-service attack is launched against the ABS MCU, potentially via CAN bus flooding or exploiting firmware vulnerabilities, leading to the unavailability of ABS functionality. Concurrently, an attacker with physical access extracts cryptographic keys from the ECU, enabling further unauthorized access and system compromise.
- **Asset at Risk**: ABS MCU (745b410a-d4aa-40d9-ac07-2d00356e4b06)
- **Cyber Loss**: Integrity

**Attack Tree Summary:**
  - **Primary Goal**: Denial of Service on ABS MCU Leading to System Unavailability
    - **Vector**: Inject Malicious CAN Messages to Overwhelm ABS MCU Processing
      - **Method**: Flood ABS MCU with high-priority CAN ID messages (e.g., 0x1A0, 0x1B0) exceeding its receive buffer or processing queue.
      - **Method**: Send malformed or invalid CAN frames with incorrect CRC or bit stuffing, forcing the ABS MCU's CAN controller into error states or reset.
      - **Method**: Repeatedly send 'Bus Off' CAN messages to disrupt normal communication and isolate the ABS MCU.
    - **Vector**: Exploit Vulnerabilities in ABS MCU Firmware via Diagnostic Interfaces
      - **Method**: Trigger a buffer overflow in a diagnostic routine (e.g., UDS ReadDataByIdentifier) through oversized data payloads, leading to MCU crash or unpredictable behavior.
      - **Method**: Perform a denial-of-service attack on the UDS $7F NRC handler, causing the ABS MCU to exhaust resources trying to process invalid service requests.
      - **Method**: Overwrite critical memory pointers or stack data within the ABS MCU's runtime environment via a specially crafted diagnostic command, causing a segmentation fault.
    - **Vector**: Induce Hardware Faults on ABS Sensor Inputs to Corrupt ABS MCU State
      - **Method**: Inject high-voltage transients onto wheel speed sensor (WSS) lines, potentially damaging the ABS MCU's input conditioning circuitry or directly causing a logic fault.
      - **Method**: Simulate erroneous WSS signals (e.g., rapid pulsing, out-of-range frequency) by manipulating the sensor output or injecting noise onto the sensor communication bus, leading to excessive interrupt load or invalid data processing by the ABS MCU.

