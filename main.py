import customtkinter as ctk
from scapy.all import sniff
from scapy.layers.inet import IP
import threading

# Setup GUI theme
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class PacketSnifferGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Simple Packet Sniffer")
        self.geometry("800x550")
        self.sniffing = False

        # Interface input
        ctk.CTkLabel(self, text="Enter Network Interface (e.g., Wi-Fi or \\Device\\NPF_{...})").pack(pady=5)
        self.iface_entry = ctk.CTkEntry(self, width=600)
        self.iface_entry.pack(pady=5)

        # Start and Stop buttons
        self.start_button = ctk.CTkButton(self, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.pack(pady=5)

        self.stop_button = ctk.CTkButton(self, text="Stop Sniffing", command=self.stop_sniffing, state="disabled")
        self.stop_button.pack(pady=5)

        # Output textbox
        self.output_box = ctk.CTkTextbox(self, width=780, height=400, font=("Consolas", 12))
        self.output_box.pack(pady=10)

    def packet_callback(self, packet):
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            protocol = packet[IP].proto
            payload = str(packet[IP].payload).strip()

            protocol_map = {
                1: 'ICMP',
                6: 'TCP',
                17: 'UDP',
            }
            protocol_name = protocol_map.get(protocol, 'Unknown')

            output = (
                f"Source IP: {ip_src}\n"
                f"Destination IP: {ip_dst}\n"
                f"Protocol: {protocol_name}\n"
                f"Payload: {payload[:50]}\n"
                + "-" * 50 + "\n"
            )
            self.output_box.insert("end", output)
            self.output_box.see("end")

    def sniff_packets(self, iface):
        sniff(iface=iface, prn=self.packet_callback, store=0, stop_filter=lambda x: not self.sniffing)

    def start_sniffing(self):
        iface = self.iface_entry.get()
        if not iface:
            self.output_box.insert("end", "⚠️ Please enter a valid interface name.\n")
            return
        self.sniffing = True
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.output_box.insert("end", f"✅ Starting capture on: {iface}\n\n")
        threading.Thread(target=self.sniff_packets, args=(iface,), daemon=True).start()

    def stop_sniffing(self):
        self.sniffing = False
        self.start_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
        self.output_box.insert("end", "🛑 Stopped packet capture.\n\n")

if __name__ == "__main__":
    app = PacketSnifferGUI()
    app.mainloop()
