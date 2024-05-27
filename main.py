import tkinter as tk
from tkinter import ttk
from queue import Queue, Empty
from threading import Thread
from scapy.all import sniff
from scapy.layers.inet import IP
from datetime import datetime
import pyodbc

class NetworkMonitorController:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Performance Monitor")

        # Create a Queue for communication between threads
        self.queue = Queue()

        # Set up database connection
        self.conn = pyodbc.connect('DRIVER={ODBC Driver 17 for SQL Server};'
                                   'SERVER=DESKTOP-8POO7R8;'
                                   'DATABASE=Capstone;'
                                   'Trusted_Connection=yes;')

        # Start the packet sniffing thread
        self.sniff_thread = Thread(target=self.start_sniffing)
        self.sniff_thread.start()

        # Set up UI components
        self.create_widgets()

    def create_widgets(self):
        # Create a Frame for packet display
        self.packet_frame = ttk.Frame(self.root)
        self.packet_frame.pack(fill=tk.BOTH, expand=True)

        # Create a Treeview for packet display
        self.packet_tree = ttk.Treeview(self.packet_frame, columns=('Timestamp', 'Source', 'Destination', 'Protocol', 'Length', 'Info'))
        self.packet_tree.heading('#0', text='Index')
        self.packet_tree.heading('Timestamp', text='Timestamp')
        self.packet_tree.heading('Source', text='Source')
        self.packet_tree.heading('Destination', text='Destination')
        self.packet_tree.heading('Protocol', text='Protocol')
        self.packet_tree.heading('Length', text='Length')
        self.packet_tree.heading('Info', text='Info')
        self.packet_tree.pack(fill=tk.BOTH, expand=True)

    def packet_callback(self, packet):
        # Check if the packet contains the IP layer
        if IP in packet:
            # Extract relevant information from the packet
            packet_data = {
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),  # Convert timestamp to string format
                'source': str(packet[IP].src),  # Access source IP address using IP.src
                'destination': str(packet[IP].dst),  # Access destination IP address using IP.dst
                'protocol': str(packet[IP].proto),  # Access protocol using IP.proto
                'length': len(packet),
                'info': packet.summary()  # Summary of packet
            }

            # Put packet data in the queue for display
            self.queue.put(packet_data)

            # Store packet data in the database
            self.store_packet_data(packet_data)

            # Calculate metrics
            self.calculate_metrics(packet_data)

        else:
            # If IP layer is not found, print a message or handle it as desired
            print("IP layer not found in packet:", packet.summary())

    def store_packet_data(self, packet_data):
        # Store packet data in the database
        cursor = self.conn.cursor()
        cursor.execute("INSERT INTO PacketData (timestamp, source, destination, protocol, length) "
                       "VALUES (?, ?, ?, ?, ?)",
                       packet_data['timestamp'], packet_data['source'], packet_data['destination'],
                       packet_data['protocol'], packet_data['length'])
        self.conn.commit()

    def calculate_metrics(self, packet_data):
        # Calculate metrics based on the received packet
        # You can implement your custom logic here
        pass

    def start_sniffing(self):
        # Sniff packets using scapy and call packet_callback for each packet
        sniff(prn=self.packet_callback, store=0)

    def update_gui(self):
        while True:
            try:
                # Get PacketData object from the queue
                packet_data = self.queue.get_nowait()

                # Display packet data in the Treeview
                self.display_packet(packet_data)

            except Empty:
                # Queue is empty, continue
                pass

            self.root.update_idletasks()
            self.root.update()

    def display_packet(self, packet_data):
        # Display packet data in the Treeview
        index = len(self.packet_tree.get_children()) + 1
        self.packet_tree.insert('', 'end', text=index, values=(
            packet_data['timestamp'],
            packet_data['source'],
            packet_data['destination'],
            packet_data['protocol'],
            packet_data['length'],
            packet_data['info']
        ))

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkMonitorController(root)
    app.update_gui()  # Start GUI update loop
    root.mainloop()
