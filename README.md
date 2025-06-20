# 🛡️ PRODIGY_CS_05 – Packet Sniffer (GUI Version)

### ✅ Internship Task - Prodigy Infotech (Cyber Security Track)

This repository contains **Task 05** of the **Prodigy Infotech Cyber Security Internship**, where I developed a **Network Packet Sniffer GUI** using **Python**, **Scapy**, and **CustomTkinter**.  
The tool captures live IP packets from a given network interface and displays source IP, destination IP, protocol, and payload data in real time.

---

## 🧠 What is a Packet Sniffer?

A packet sniffer is a tool that monitors network traffic by capturing packets traveling over a network. It is widely used for:
- 🌐 Network analysis and troubleshooting
- 🛡️ Security monitoring
- 👨‍🏫 Ethical hacking and research

---

## 🎯 Features of This Project

- ✅ Live packet capture with GUI control  
- 🌐 Displays IP source, destination, protocol (TCP/UDP/ICMP)  
- 📦 Shows first 50 characters of packet payload  
- 🖥️ Built with modern `customtkinter` GUI  
- ⚙️ Simple interface input to choose your network adapter

---

## 📂 File Structure

```bash
PRODIGY_CS_05/
├── README.md           # Project documentation    
└── main.py             # Main GUI-based packet sniffer
```

---

## 🖥️ GUI Preview

![image](https://github.com/user-attachments/assets/b2e8c726-e591-4811-a56f-27180fedd14b)

---


## 🛠️ How to Run

### ⚙️ Prerequisites:
- Python 3.x
- scapy
- customtkinter
- Windows with Npcap installed (in WinPcap API mode)

### 🧪 Steps:
```bash
git clone https://github.com/YashYadav579/PRODIGY_CS_05.git
cd PRODIGY_CS_05
pip install customtkinter scapy
python main.py
```
✅ Run as Administrator (required to access interfaces via Scapy on Windows)

---

## 🧪 Example Output

```bash
Source IP: 192.168.1.10
Destination IP: 192.168.1.1
Protocol: TCP
Payload: GET / HTTP/1.1...
--------------------------------------------------
```

---

## ⚠️ Ethical Use Only

⚠️ This project is intended for **educational purposes only**.  
Do **not** use this software without the **user’s full knowledge and consent**.  
**Unauthorized use of keyloggers is illegal and unethical.**

---

## 🙋‍♂️ About Me

**Name**: _Yash Yadav_  
**Intern** @ **Prodigy Infotech** – Cyber Security Track  
**Task**: Packet Sniffer using Python GUI   
**Task ID**: PRODIGY_CS_05  

---

## 🔗 Connect with Me

- 💼 [LinkedIn](https://www.linkedin.com/in/yashyadav-5790abc/)
- 💻 [GitHub](https://github.com/YashYadav579)

---

## 🏁 Conclusion

This project enhanced my skills in:
- Working with raw network traffic using scapy
- GUI design using customtkinter
- Real-time threading & event handling in Python
- Ethical cybersecurity practices

Thanks to Prodigy Infotech for another valuable learning opportunity!
