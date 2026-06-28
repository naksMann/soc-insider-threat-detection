SOC Insider Threat Detection Using Wazuh and Machine Learning
=
A small Security Operations Centre lab that detects insider threats through file activity. Wazuh handles file integrity monitoring across several simulated users, and an Isolation Forest model flags the behaviour that does not fit each user's normal pattern.

Why this project
=
Most security tooling is built to catch intruders coming from outside the network. Insider threats break that assumption. The person already has a valid account and a reason to be there, so signature based rules stay quiet while they copy data or touch files they normally never use. This lab takes a different route: it watches what files users touch, learns what normal looks like, and flags the deviations.

How it works
=
The whole environment runs in Docker, which keeps it light enough for a single machine and easy to reset between tests.
_______________________________________________________________________________________________
Component	                    |          Role
_______________________________________________________________________________________________
Docker containers	            |         Simulated end users generating file activity
_______________________________________________________________________________________________
Wazuh Manager	                |         Central SOC that collects and analyses events
_______________________________________________________________________________________________
Syscheck	                    |         File Integrity Monitoring engine inside Wazuh
_______________________________________________________________________________________________
Isolation Forest	            |         Machine learning model that scores anomalies
_______________________________________________________________________________________________

Four agents run in the lab: two normal users (`user_day_1`, `user_day_2`), one `insider` that performs the suspicious behaviour, and the `wazuh-server` manager.

Detection approach
=
Syscheck monitors sensitive paths such as `/data` and records every file creation, modification, and deletion. The insider agent simulates a data thief by writing unusually large files into that directory, the kind of activity you would see when someone aggregates documents before exfiltration.

The Isolation Forest model scores each event using five features:
- File size (the strongest insider signal)
- Event type (created or modified)
- File path depth
- Privilege level (root vs user)
- Permission length
  
Because it is unsupervised, the model needs no labelled examples of bad behaviour. It learns the baseline and isolates whatever stands out, which fits how real security data actually looks.

Results
=
The Wazuh dashboard presents detection in three views: pie charts of alerts per agent, tables of the detailed events behind each alert, and a bar graph of agent against event count where the insider's spike stands out next to the quieter baseline users.

Repository contents
=
```
soc-insider-threat-detection/
├── README.md
├── docs/
    └── SOC_Insider_Threat_Detection_Report.pdf
```
Tools used
=

Wazuh, Syscheck, Docker, Python, scikit-learn (Isolation Forest)

Demo
=
Walkthrough Video : https://youtu.be/WY-QnTTFSOU

Author
=

Nakedi Tumelo Peta (naksMann)

Cybersecurity Intern, 4IR Lab

Computer Systems Engineering, Tshwane University of Technology
