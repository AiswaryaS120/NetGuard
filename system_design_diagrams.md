# NetGuard — System Design & Diagrams

> [!NOTE]
> All diagrams below are rendered using Mermaid. For your report, **redraw these as polished figures** using tools like draw.io, Lucidchart, or Visio, then insert them as images at 300 DPI.

---

## 1. System Architecture Diagram

This is the top-level view of how NetGuard's components connect.

```mermaid
graph TB
    subgraph "Network Layer"
        NIC["Network Interface Card<br/>(Wi-Fi / Ethernet)"]
    end

    subgraph "Data Acquisition Layer"
        ST["SnifferThread<br/>(network_engine.py)"]
        TM["TrafficMonitor<br/>(Sliding Window Stats)"]
    end

    subgraph "Detection Layer"
        ML["ML Engine<br/>(ml_engine.py)"]
        RE["Rule Engine<br/>(rule_engine.py)"]
        subgraph "ML Pipeline"
            RF["Stage 1: Random Forest<br/>(Known Attack Classification)"]
            IF["Stage 2: Isolation Forest<br/>(Zero-Day Detection)"]
        end
        subgraph "Rule Checks"
            SYN["SYN Flood Detector"]
            DDOS["DDoS/Volume Detector"]
            PS["Port Scan Detector"]
        end
    end

    subgraph "Communication Layer"
        Q["Thread-Safe Queue<br/>(queue.Queue)"]
    end

    subgraph "Presentation Layer"
        GUI["NetGuard Dashboard<br/>(gui_dashboard.py)"]
        subgraph "Dashboard Components"
            HUD["HUD Metric Cards"]
            CHART["Traffic & Threat Charts"]
            PKT["Packet Stream Table"]
            ALR["Intrusion Alert Panel"]
        end
    end

    subgraph "Orchestration"
        MAIN["main.py"]
        SM["SnifferManager"]
    end

    NIC -->|"Raw Packets<br/>(Promiscuous Mode)"| ST
    ST --> TM
    TM -->|"14-Feature Vector"| ML
    ST -->|"Packet Data"| RE
    ML --> RF
    RF -->|"Normal?"| IF
    RF -->|"Attack Detected"| Q
    IF -->|"Zero-Day / Normal"| Q
    RE --> SYN & DDOS & PS
    SYN & DDOS & PS -->|"Alert / None"| Q
    Q -->|"Every 500ms"| GUI
    GUI --> HUD & CHART & PKT & ALR
    MAIN --> SM
    SM -->|"Start / Stop"| ST

    style NIC fill:#1e3a5f,stroke:#4A9EFF,color:#fff
    style ML fill:#2d1f3d,stroke:#6C8EFF,color:#fff
    style RE fill:#3d1f1f,stroke:#E5484D,color:#fff
    style GUI fill:#1f3d2d,stroke:#46A758,color:#fff
    style Q fill:#3d3d1f,stroke:#E5A340,color:#fff
    style MAIN fill:#2a3040,stroke:#9BA4B5,color:#fff
```

---

## 2. Data Flow Diagram (DFD) — Level 0

The context-level DFD showing NetGuard as a single process.

```mermaid
graph LR
    NET(("Network<br/>Traffic"))
    USER(("User /<br/>Administrator"))
    NETGUARD["NetGuard<br/>IDS System"]
    CSV[("CSV<br/>Export File")]

    NET -->|"Raw Packets"| NETGUARD
    NETGUARD -->|"Alerts, Threat Level,<br/>Packet Stream, Charts"| USER
    USER -->|"Start / Stop / Simulate"| NETGUARD
    NETGUARD -->|"Traffic Logs"| CSV
    USER -->|"Export Request"| NETGUARD

    style NETGUARD fill:#1e2330,stroke:#6C8EFF,color:#fff
    style NET fill:#1f3d2d,stroke:#46A758,color:#fff
    style USER fill:#3d1f1f,stroke:#E5484D,color:#fff
    style CSV fill:#3d3d1f,stroke:#E5A340,color:#fff
```

---

## 3. Data Flow Diagram (DFD) — Level 1

Breaks NetGuard into its internal processes.

```mermaid
graph TD
    NET(("Network<br/>Traffic"))
    USER(("User"))

    P1["1.0<br/>Packet Capture<br/>(SnifferThread)"]
    P2["2.0<br/>Feature Extraction<br/>(TrafficMonitor)"]
    P3["3.0<br/>ML Classification<br/>(AnomalyDetector)"]
    P4["4.0<br/>Rule-Based Detection<br/>(LogicEngine)"]
    P5["5.0<br/>Dashboard Display<br/>(NetGuardDashboard)"]

    DS1[("IP History<br/>Store")]
    DS2[("Connection<br/>Window")]
    DS3[("ML Models<br/>(RF + IF + Scaler)")]
    DS4[("Rate History<br/>Store")]
    DS5[("Data Queue")]

    NET -->|"Raw Packets"| P1
    P1 -->|"Packet Info<br/>(5-tuple + flags)"| P2
    P2 <-->|"Read/Write Timestamps"| DS1
    P2 <-->|"Read/Write Connections"| DS2
    P2 -->|"14-Feature Vector"| P3
    P3 <-->|"Load Models"| DS3
    P3 -->|"Prediction Label<br/>(DoS/Scan/Normal/Zero-Day)"| DS5
    P1 -->|"Simplified Packet"| P4
    P4 <-->|"Read/Write Rates"| DS4
    P4 -->|"Alert Message"| DS5
    DS5 -->|"Enriched Packets<br/>(every 500ms)"| P5
    P5 -->|"Dashboard View"| USER
    USER -->|"Start/Stop/Simulate/Export"| P5

    style P1 fill:#1e3a5f,stroke:#4A9EFF,color:#fff
    style P2 fill:#1e3a5f,stroke:#4A9EFF,color:#fff
    style P3 fill:#2d1f3d,stroke:#6C8EFF,color:#fff
    style P4 fill:#3d1f1f,stroke:#E5484D,color:#fff
    style P5 fill:#1f3d2d,stroke:#46A758,color:#fff
```

---

## 4. Use Case Diagram

```mermaid
graph LR
    subgraph "NetGuard System"
        UC1["Start Monitoring"]
        UC2["Stop Monitoring"]
        UC3["View Live Dashboard"]
        UC4["View Packet Stream"]
        UC5["View Intrusion Alerts"]
        UC6["View Threat Level"]
        UC7["Simulate DoS Attack"]
        UC8["Simulate Port Scan"]
        UC9["Simulate Brute Force"]
        UC10["Simulate Normal Traffic"]
        UC11["Export Logs to CSV"]
        UC12["Detect Known Attacks<br/>(Random Forest)"]
        UC13["Detect Zero-Day Attacks<br/>(Isolation Forest)"]
        UC14["Detect SYN Flood<br/>(Rule Engine)"]
        UC15["Detect DDoS<br/>(Rule Engine)"]
        UC16["Detect Port Scan<br/>(Rule Engine)"]
    end

    ADMIN(("👤 User /<br/>Administrator"))
    SYS(("⚙️ System<br/>(Automated)"))

    ADMIN --> UC1
    ADMIN --> UC2
    ADMIN --> UC3
    ADMIN --> UC4
    ADMIN --> UC5
    ADMIN --> UC6
    ADMIN --> UC7
    ADMIN --> UC8
    ADMIN --> UC9
    ADMIN --> UC10
    ADMIN --> UC11

    SYS --> UC12
    SYS --> UC13
    SYS --> UC14
    SYS --> UC15
    SYS --> UC16

    UC12 -.->|"includes"| UC5
    UC13 -.->|"includes"| UC5
    UC14 -.->|"includes"| UC5
    UC15 -.->|"includes"| UC5
    UC16 -.->|"includes"| UC5

    style ADMIN fill:#1e3a5f,stroke:#4A9EFF,color:#fff
    style SYS fill:#3d1f1f,stroke:#E5484D,color:#fff
```

---

## 5. Sequence Diagram — Packet Processing Pipeline

Shows the exact order of operations when a single packet arrives.

```mermaid
sequenceDiagram
    participant NIC as Network Interface
    participant ST as SnifferThread
    participant PP as process_packet()
    participant TM as TrafficMonitor
    participant ML as AnomalyDetector
    participant RF as Random Forest
    participant IF as Isolation Forest
    participant RE as LogicEngine
    participant Q as Data Queue
    participant GUI as Dashboard

    NIC->>ST: Raw packet captured (Scapy sniff)
    ST->>PP: packet_callback(packet)

    Note over PP: Check: packet has IP layer?
    PP->>PP: Extract 5-tuple + TCP flags

    PP->>TM: update_and_get_features(packet_info)
    Note over TM: Clean old timestamps (>2s)
    Note over TM: Update ip_history, service_history
    Note over TM: Update connection_window
    TM->>TM: Compute 14 features
    TM-->>PP: Return [f1, f2, ..., f14]

    PP-->>ST: Return features dict

    Note over ST: === ML PREDICTION ===
    ST->>ML: predict(features)

    Note over ML: Warmup check (< 5s → "normal")
    ML->>RF: Stage 1: predict_proba(X)
    RF-->>ML: P(attack) = 0.87

    alt P(attack) >= 0.45
        ML->>ML: _classify_attack_type()
        Note over ML: Noise filter: count >= threshold?
        ML-->>ST: "DoS Attack"
    else P(attack) < 0.45 (RF says normal)
        ML->>IF: Stage 2: predict(X)
        alt IF predicts -1 (anomaly)
            IF->>IF: decision_function(X)
            Note over IF: count>=50 AND score<-0.05?
            IF-->>ML: "Zero-Day Attack"
        else IF predicts 1 (normal)
            IF-->>ML: "normal"
        end
    end

    ML-->>ST: anomaly label

    Note over ST: === RULE CHECK ===
    ST->>RE: check_packet(simple_data)
    Note over RE: Update per-IP stats
    Note over RE: Check: Port Scan → SYN Flood → DDoS
    RE-->>ST: alert_msg or None

    ST->>Q: queue.put(enriched_features)

    Note over GUI: Every 500ms tick
    Q-->>GUI: GUI drains queue
    GUI->>GUI: Update HUD, Charts, Alerts
    GUI->>GUI: Compute threat level
    GUI->>GUI: Render dashboard
```

---

## 6. Class Diagram

```mermaid
classDiagram
    class SnifferManager {
        -queue: Queue
        -detector: AnomalyDetector
        -logic_engine: LogicEngine
        -thread: SnifferThread
        +start()
        +stop()
    }

    class SnifferThread {
        -data_queue: Queue
        -stop_event: Event
        -daemon: bool = True
        -monitor: TrafficMonitor
        -logic_engine: LogicEngine
        -detector: AnomalyDetector
        +process_packet(packet): dict
        +packet_callback(packet)
        +run()
        +stop()
        -_get_best_iface(): tuple
    }

    class TrafficMonitor {
        -lock: Lock
        -ip_history: defaultdict[list]
        -service_history: defaultdict[list]
        -connection_window: deque[maxlen=300]
        +update_and_get_features(packet_info): list[14]
    }

    class AnomalyDetector {
        -model_path: str
        -encoder_path: str
        -scaler_path: str
        -iforest_path: str
        -model: RandomForestClassifier
        -iforest: IsolationForest
        -encoder: LabelEncoder
        -scaler: StandardScaler
        -start_time: float
        +load_model()
        +predict(features_dict): str
        -_classify_attack_type(count, srv_count, serror_rate, same_srv_rate, diff_srv_rate, confidence): str
        +simple_heuristic(features): str
    }

    class LogicEngine {
        -LEARNING_WINDOW: int = 20
        -SYN_K: float = 3.0
        -DDOS_K: float = 3.0
        -DEFAULT_SYN_MEAN: float = 10.0
        -DEFAULT_SYN_STD: float = 3.0
        -DEFAULT_DDOS_MEAN: float = 1000.0
        -DEFAULT_DDOS_STD: float = 300.0
        -MIN_DDOS_THRESHOLD: int = 50
        -MIN_SYN_THRESHOLD: int = 30
        -SCAN_THRESHOLD: int = 20
        -SCAN_WINDOW: float = 3.0
        -COMMON_WEB_PORTS: set
        -ALERT_COOLDOWN: float = 5.0
        -ip_stats: defaultdict
        -scan_hits: defaultdict
        -last_alert_at: dict
        +check_packet(packet_data): str or None
        -_calculate_threshold(history, def_mean, def_std, k, min_floor): float
        -_can_alert(src_ip, alert_type, now): bool
        -_update_scan_hits(key, dst_port, now)
    }

    class NetGuardDashboard {
        -start_callback: Callable
        -stop_callback: Callable
        -log_queue: Queue
        -is_running: bool
        -traffic_log: deque[maxlen=10000]
        -traffic_history: deque[maxlen=60]
        -threat_history: deque[maxlen=60]
        -last_anomaly_time: float
        -last_anomaly_type: str
        -packet_count: int
        -pulse_state: bool
        +create_sidebar()
        +create_header()
        +create_main_view()
        +create_status_bar()
        +simulate_attack(attack_type)
        +on_start()
        +on_stop()
        +log_interface(msg, is_alert, data)
        +update_hud_val(card, value, color)
        +update_ui_loop()
        +generate_report()
    }

    SnifferManager "1" *-- "0..1" SnifferThread : manages
    SnifferThread "1" *-- "1" TrafficMonitor : contains
    SnifferThread "1" o-- "0..1" AnomalyDetector : uses
    SnifferThread "1" o-- "0..1" LogicEngine : uses
    SnifferManager "1" o-- "1" AnomalyDetector : holds ref
    SnifferManager "1" o-- "1" LogicEngine : holds ref
    NetGuardDashboard ..> SnifferManager : "start/stop via callbacks"
```

---

## 7. Activity Diagram — Threat Detection Flow

Shows the complete decision logic for a single packet.

```mermaid
flowchart TD
    START(("Packet Arrives"))
    A{"Has IP Layer?"}
    B{"src_ip == 0.0.0.0?<br/>(DHCP)"}
    C["Extract 5-tuple<br/>(src_ip, dst_ip, src_port, dst_port, protocol)<br/>+ TCP Flags"]
    D["TrafficMonitor:<br/>Compute 14 Features"]
    E{"ML Model<br/>Loaded?"}
    F{"Warmup Period<br/>(< 5 seconds)?"}

    G["Scale Features<br/>(StandardScaler)"]
    H["Stage 1: Random Forest<br/>predict_proba(X)"]
    I{"P(attack)<br/>>= 0.45?"}
    J["_classify_attack_type()<br/>→ DoS / Scan / Brute Force"]
    K{"Noise Filter<br/>count >= threshold?"}
    L["Stage 2: Isolation Forest<br/>predict(X)"]
    M{"IF predicts<br/>-1 (outlier)?"}
    N{"count >= 50<br/>AND score < -0.05?"}

    O["Rule Engine:<br/>check_packet()"]
    P{"Port Scan?<br/>(> 20 unique ports)"}
    Q{"SYN Flood?<br/>(SYN/s > threshold)"}
    R{"DDoS/Volume?<br/>(pkt/s > threshold<br/>AND diversity < 0.2<br/>AND consecutive >= 2)"}

    RES_ATK["🔴 ATTACK DETECTED<br/>(ML Label + Rule Alert)"]
    RES_ZD["🟡 ZERO-DAY DETECTED"]
    RES_RULE["🔴 RULE ALERT<br/>(SYN Flood / DDoS / Scan)"]
    RES_NORM["🟢 NORMAL"]

    QUEUE["Put in Data Queue →<br/>Dashboard Display"]

    START --> A
    A -->|No| RES_NORM
    A -->|Yes| B
    B -->|Yes| RES_NORM
    B -->|No| C
    C --> D

    D --> E
    E -->|No| O
    E -->|Yes| F
    F -->|Yes| O
    F -->|No| G
    G --> H
    H --> I
    I -->|Yes| J
    J --> K
    K -->|Yes| RES_ATK
    K -->|No| O
    I -->|No| L
    L --> M
    M -->|No| O
    M -->|Yes| N
    N -->|Yes| RES_ZD
    N -->|No| O

    O --> P
    P -->|Yes| RES_RULE
    P -->|No| Q
    Q -->|Yes| RES_RULE
    Q -->|No| R
    R -->|Yes| RES_RULE
    R -->|No| RES_NORM

    RES_ATK --> QUEUE
    RES_ZD --> QUEUE
    RES_RULE --> QUEUE
    RES_NORM --> QUEUE

    style RES_ATK fill:#3d1f1f,stroke:#E5484D,color:#fff
    style RES_ZD fill:#3d3d1f,stroke:#E5A340,color:#fff
    style RES_RULE fill:#3d1f1f,stroke:#E5484D,color:#fff
    style RES_NORM fill:#1f3d2d,stroke:#46A758,color:#fff
    style START fill:#1e3a5f,stroke:#4A9EFF,color:#fff
```

---

## 8. State Diagram — Dashboard Threat Level

Shows how the dashboard transitions between threat states.

```mermaid
stateDiagram-v2
    [*] --> Secure

    Secure --> Critical : DoS / Brute Force / Privilege Escalation / Zero-Day detected\nOR packets_per_tick > 50
    Secure --> Moderate : Port Scan detected\nOR low-severity anomaly

    Moderate --> Critical : High-severity attack detected
    Moderate --> Secure : No anomaly for ~10 seconds\n(threat decays: t × 0.92 per 500ms tick)

    Critical --> Moderate : No new anomaly\n(threat decays below 0.8)
    Critical --> Critical : New attack keeps refreshing\n(threat stays at 1.0)

    Moderate --> Moderate : Threat score between 0.3 and 0.8

    state Secure {
        [*] --> display_green
        display_green : Threat Card = "Secure" (Green)
        display_green : Border = default
        display_green : Chart line = green
    }

    state Moderate {
        [*] --> display_amber
        display_amber : Threat Card = "Moderate" (Amber)
        display_amber : Border = amber
        display_amber : Chart line = amber
    }

    state Critical {
        [*] --> pulse_on
        pulse_on --> pulse_off : 500ms tick
        pulse_off --> pulse_on : 500ms tick
        pulse_on : Threat Card = "Critical" (Red)
        pulse_on : Border = RED (pulse ON)
        pulse_off : Threat Card = "Critical" (Red)
        pulse_off : Border = dark red (pulse OFF)
    }
```

**Threat Level Thresholds:**
| State | Threat Score Range | Trigger |
|---|---|---|
| Secure | 0.0 – 0.29 | No anomaly or decayed below 0.3 |
| Moderate | 0.3 – 0.79 | Low-severity anomaly (e.g., Port Scan) |
| Critical | 0.8 – 1.0 | High-severity attack (DoS, DDoS, Zero-Day) |

**Decay Formula:** `threat(t) = threat(t-1) × 0.92` (when no active anomaly)
- Critical → Moderate: ~2.5 seconds
- Critical → Secure: ~10 seconds

---

## 9. Component Diagram

Shows physical module dependencies and communication.

```mermaid
graph LR
    subgraph "Core Application"
        MAIN["main.py<br/>(Entry Point)"]
        NE["network_engine.py<br/>(Packet Capture)"]
        MLE["ml_engine.py<br/>(ML Prediction)"]
        RUE["rule_engine.py<br/>(Rule Detection)"]
        GUI["gui_dashboard.py<br/>(Dashboard UI)"]
    end

    subgraph "Training Pipeline"
        TS["train_supervised.py<br/>(RF Training)"]
        TM["train_model.py<br/>(IF Training)"]
    end

    subgraph "Model Artifacts (.pkl)"
        RF_M["rf_model.pkl<br/>(Random Forest)"]
        IF_M["iforest_model.pkl<br/>(Isolation Forest)"]
        SC["scaler.pkl<br/>(StandardScaler)"]
        LE["label_encoder.pkl<br/>(LabelEncoder)"]
    end

    subgraph "Dataset"
        TRAIN["KDDTrain+.txt<br/>(125,973 records)"]
        TEST["KDDTest+.txt<br/>(22,544 records)"]
    end

    subgraph "External Libraries"
        SCAPY["Scapy"]
        SKLEARN["Scikit-learn"]
        CTK["CustomTkinter"]
        MPL["Matplotlib"]
        PSUTIL["Psutil"]
    end

    MAIN --> NE
    MAIN --> MLE
    MAIN --> RUE
    MAIN --> GUI

    NE --> SCAPY
    NE --> MLE
    NE --> RUE

    MLE --> RF_M
    MLE --> IF_M
    MLE --> SC
    MLE --> LE
    MLE --> SKLEARN

    GUI --> CTK
    GUI --> MPL
    GUI --> PSUTIL

    TS --> TRAIN
    TS --> RF_M
    TS --> SC
    TS --> LE
    TS --> SKLEARN

    TM --> TRAIN
    TM --> SC
    TM --> IF_M
    TM --> SKLEARN

    style MAIN fill:#2a3040,stroke:#9BA4B5,color:#fff
    style NE fill:#1e3a5f,stroke:#4A9EFF,color:#fff
    style MLE fill:#2d1f3d,stroke:#6C8EFF,color:#fff
    style RUE fill:#3d1f1f,stroke:#E5484D,color:#fff
    style GUI fill:#1f3d2d,stroke:#46A758,color:#fff
```

---

## 10. ML Pipeline Detail — Two-Stage Cascaded Architecture

```mermaid
graph TD
    INPUT["Incoming Packet<br/>(14 Features)"]
    SCALE["StandardScaler<br/>z = (x - μ) / σ"]

    subgraph "STAGE 1 — Random Forest (Known Attacks)"
        RF["300 Decision Trees<br/>(Binary: Normal vs Attack)"]
        PROBA{"P(attack)<br/>>= 0.45?"}
        CLASSIFY["_classify_attack_type()<br/>Feature-Pattern Rules"]
        NOISE{"Noise Filter<br/>count >= threshold?"}
    end

    subgraph "STAGE 2 — Isolation Forest (Zero-Day)"
        direction TB
        IF_CHECK["200 Isolation Trees<br/>(Trained on Normal Only)"]
        IF_PRED{"Prediction<br/>== -1?"}
        IF_SCORE{"count >= 50<br/>AND<br/>score < -0.05?"}
    end

    KNOWN["✓ Known Attack<br/>(DoS / Scan / Brute Force)"]
    ZERODAY["✓ Zero-Day Attack"]
    NORMAL["✓ Normal Traffic"]
    FALLBACK["→ Rule Engine Only"]

    INPUT --> SCALE
    SCALE --> RF
    RF --> PROBA
    PROBA -->|"Yes"| CLASSIFY
    CLASSIFY --> NOISE
    NOISE -->|"Pass"| KNOWN
    NOISE -->|"Fail (low volume)"| FALLBACK

    PROBA -->|"No (RF says normal)"| IF_CHECK
    IF_CHECK --> IF_PRED
    IF_PRED -->|"Yes (outlier)"| IF_SCORE
    IF_SCORE -->|"Yes"| ZERODAY
    IF_SCORE -->|"No"| FALLBACK
    IF_PRED -->|"No (inlier)"| FALLBACK

    FALLBACK --> NORMAL

    style KNOWN fill:#3d1f1f,stroke:#E5484D,color:#fff
    style ZERODAY fill:#3d3d1f,stroke:#E5A340,color:#fff
    style NORMAL fill:#1f3d2d,stroke:#46A758,color:#fff
    style INPUT fill:#1e3a5f,stroke:#4A9EFF,color:#fff
```

**Attack Classification Rules (Priority Order):**

| Priority | Condition | Classification |
|---|---|---|
| 1 | serror_rate > 0.5 AND count > 50 | DoS Attack |
| 2 | diff_srv_rate > 0.5 AND count > 10 | Port Scan |
| 3 | count > 15 AND srv_count < count × 0.2 | Port Scan |
| 4 | same_srv_rate > 0.8 AND serror_rate < 0.3 AND count < 300 | Brute Force/Malware |
| 5 | count > 300 AND same_srv_rate > 0.8 | DoS Attack |
| 6 | confidence > 0.85 AND count > 100 | DoS Attack |
| 7 | confidence > 0.5 AND count > 10 | Brute Force/Malware |
| 8 | Default catch-all | DoS Attack |

---

## 11. Rule Engine — Dynamic Threshold Detection Logic

```mermaid
flowchart TD
    PKT(("Packet<br/>Arrives"))

    SEC{"Elapsed<br/>>= 1 second?"}
    COMMIT["Commit current counters<br/>to history deques<br/>Fill missed seconds with 0"]
    RESET["Reset current_syn = 0<br/>current_pkt = 0<br/>current_flows = set()"]

    UPDATE["current_pkt += 1<br/>Add flow to current_flows"]
    SYN_CHK{"'S' in flag<br/>AND 'A' not in flag?"}
    SYN_INC["current_syn += 1"]

    PS_CHK{"dst_port is SYN<br/>AND not web port<br/>(80, 443, 8080, 8443)?"}
    PS_UPD["Track (src, dst, port)<br/>in scan_hits"]
    PS_COUNT{"unique_ports<br/>> 20?"}
    PS_ALERT["🔴 PORT SCAN ALERT"]

    SYN_THRESH["Compute SYN threshold<br/>T = Mean + 3.0 × StdDev<br/>min = 30"]
    SYN_OVER{"current_syn<br/>> threshold?"}
    SYN_ALERT["🔴 SYN FLOOD ALERT"]

    DDOS_THRESH["Compute DDoS threshold<br/>T = Mean + 3.0 × StdDev<br/>min = 50 (300 for web ports)"]
    DDOS_OVER{"current_pkt > threshold<br/>AND diversity < 0.2<br/>AND consecutive >= 2?"}
    DDOS_ALERT["🔴 DDoS/DoS FLOOD ALERT"]

    DONE["No Alert → return None"]

    PKT --> SEC
    SEC -->|Yes| COMMIT --> RESET --> UPDATE
    SEC -->|No| UPDATE
    UPDATE --> SYN_CHK
    SYN_CHK -->|Yes| SYN_INC --> PS_CHK
    SYN_CHK -->|No| PS_CHK

    PS_CHK -->|Yes| PS_UPD --> PS_COUNT
    PS_COUNT -->|Yes| PS_ALERT
    PS_COUNT -->|No| SYN_THRESH

    PS_CHK -->|No / Web Port| SYN_THRESH
    SYN_THRESH --> SYN_OVER
    SYN_OVER -->|Yes| SYN_ALERT
    SYN_OVER -->|No| DDOS_THRESH
    DDOS_THRESH --> DDOS_OVER
    DDOS_OVER -->|Yes| DDOS_ALERT
    DDOS_OVER -->|No| DONE

    style PS_ALERT fill:#3d1f1f,stroke:#E5484D,color:#fff
    style SYN_ALERT fill:#3d1f1f,stroke:#E5484D,color:#fff
    style DDOS_ALERT fill:#3d1f1f,stroke:#E5484D,color:#fff
    style DONE fill:#1f3d2d,stroke:#46A758,color:#fff
    style PKT fill:#1e3a5f,stroke:#4A9EFF,color:#fff
```

**Threshold Equation:**
```
     ┌─────────────────────────────────────────────────────┐
     │  Threshold = Mean(history) + K × StdDev(history)    │
     │                                                     │
     │  Where:                                             │
     │    K = 3.0 (3-sigma → 99.7% confidence)             │
     │    history = last 20 seconds of per-IP rates         │
     │    If history < 2 samples → use defaults             │
     │    Result is clamped to: max(computed, safety_floor) │
     └─────────────────────────────────────────────────────┘
```

---

## 12. ER Diagram — In-Memory Data Structures

NetGuard uses no traditional database but maintains structured in-memory stores.

```mermaid
erDiagram
    IP_HISTORY {
        string src_ip PK
        float[] timestamps "Packet arrival times (2s window)"
    }

    SERVICE_HISTORY {
        string src_ip PK
        float time "Timestamp"
        string dst_ip "Destination"
        int service "Destination port"
    }

    CONNECTION_WINDOW {
        string src "Source IP"
        string dst "Destination IP"
        int service "Destination port"
        string flag "TCP flags"
    }

    IP_STATS {
        string src_ip PK
        int[] syn_history "SYN/sec for last 20s"
        int[] pkt_history "Packets/sec for last 20s"
        int current_syn "SYN count this second"
        int current_pkt "Packet count this second"
        string_set current_flows "Unique flows this second"
        int dos_consecutive "Consecutive DoS threshold breaches"
        float last_sec_time "Start of current second"
    }

    SCAN_HITS {
        string src_ip PK
        string dst_ip PK
        float timestamp "Hit time"
        int dst_port "Scanned port"
    }

    TRAFFIC_LOG {
        float timestamp
        string src_ip
        string dst_ip
        int protocol
        int src_port
        int dst_port
        string anomaly "ML prediction label"
        string rule_alert "Rule engine alert"
    }

    IP_HISTORY ||--o{ SERVICE_HISTORY : "per src_ip"
    IP_STATS ||--o{ SCAN_HITS : "per src_ip"
    CONNECTION_WINDOW }o--|| IP_HISTORY : "references"
    TRAFFIC_LOG }o--|| IP_HISTORY : "derived from"
```

---

## Summary — Diagrams for Report

| Figure # | Diagram Type | Where to Use in Report |
|---|---|---|
| Fig 4.1 | System Architecture | Chapter IV (Section 4.1) |
| Fig 4.2 | DFD Level 0 | Chapter IV (Section 4.2) |
| Fig 4.3 | DFD Level 1 | Chapter IV (Section 4.2) |
| Fig 4.4 | Use Case Diagram | Chapter IV (Section 4.3) |
| Fig 4.5 | Sequence Diagram | Chapter IV (Section 4.3) |
| Fig 4.6 | Class Diagram | Chapter IV (Section 4.3) |
| Fig 4.7 | Activity Diagram | Chapter IV (Section 4.3) |
| Fig 4.8 | State Diagram (Threat Levels) | Chapter IV (Section 4.4) |
| Fig 4.9 | Component Diagram | Chapter IV (Section 4.2) |
| Fig 5.1 | ML Pipeline Detail | Chapter V (Section 5.3) |
| Fig 5.2 | Rule Engine Logic Flow | Chapter V (Section 5.4) |
| Fig 4.10 | ER Diagram (Data Structures) | Chapter IV (Section 4.4) |

> [!TIP]
> For your report, redraw these diagrams using **draw.io** (free, exports to high-res PNG). The Mermaid versions here are for reference and accuracy — the visual layout in draw.io will be cleaner for print.
