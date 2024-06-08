import tkinter as tk
from tkinter import ttk
from queue import Queue, Empty
from threading import Thread
from scapy.all import sniff
from scapy.layers.inet import IP
from datetime import datetime
import pyodbc
import time
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

PROTOCOLS = {
    1: 'ICMP',
    6: 'TCP',
    17: 'UDP',
    2: 'IGMP',
    47: 'GRE',
    50: 'ESP',
    51: 'AH',
    89: 'OSPF',
    132: 'SCTP'
}

class NetworkMonitorController:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Performance Monitor")

        # Create a Queue for communication between threads
        self.queue = Queue()
        self.metrics_queue = Queue()

        # Set up database connection
        self.conn = pyodbc.connect('DRIVER={ODBC Driver 17 for SQL Server};'
                                   'SERVER=DESKTOP-8POO7R8;'
                                   'DATABASE=Capstone;'
                                   'Trusted_Connection=yes;')

        # Initialize metrics
        self.packet_count = 0
        self.total_data_length = 0
        self.start_time = datetime.now()

        # Labels to display metrics
        self.packet_rate_label = None
        self.bandwidth_usage_label = None

        # Filter criteria
        self.filter_text = tk.StringVar()

        # Packet storage for filtering
        self.packets = []

        # Start the packet sniffing thread
        self.sniff_thread = Thread(target=self.start_sniffing)
        self.sniff_thread.start()

        # Set up UI components
        self.create_widgets()

    def create_widgets(self):
        # Create a Frame for filter entry
        self.filter_frame = ttk.Frame(self.root)
        self.filter_frame.pack(fill=tk.X)

        # Add a label next to the filter entry
        self.filter_label = ttk.Label(self.filter_frame, text="Apply a display filter:")
        self.filter_label.pack(side=tk.LEFT, padx=(10, 0), pady=5)

        # Create an Entry widget for filter criteria
        self.filter_entry = ttk.Entry(self.filter_frame, textvariable=self.filter_text)
        self.filter_entry.pack(side=tk.LEFT, fill=tk.X, padx=10, pady=5)
        self.filter_entry.bind('<Return>', self.apply_filter)

        # Add a button to apply the filter
        self.filter_button = ttk.Button(self.filter_frame, text="Apply Filter", command=self.apply_filter)
        self.filter_button.pack(side=tk.LEFT, padx=10, pady=5)

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

        # Create a Frame for metrics display
        self.metrics_frame = ttk.Frame(self.root)
        self.metrics_frame.pack(fill=tk.BOTH, expand=True)

        # Add labels to display metrics
        self.packet_rate_label = ttk.Label(self.metrics_frame, text="Packet Rate: N/A")
        self.packet_rate_label.pack(side=tk.LEFT, padx=10)

        self.bandwidth_usage_label = ttk.Label(self.metrics_frame, text="Bandwidth Usage: N/A")
        self.bandwidth_usage_label.pack(side=tk.LEFT, padx=10)

        # Create a frame for the graphs
        self.graph_frame = ttk.Frame(self.root)
        self.graph_frame.pack(fill=tk.BOTH, expand=True)

        # Set up Matplotlib Figure and Axes
        self.figure = Figure(figsize=(15, 5), dpi=100)
        self.ax1 = self.figure.add_subplot(121)
        self.ax2 = self.ax1.twinx()
        self.ax3 = self.figure.add_subplot(122)
        self.ax4 = self.ax3.twinx()
        self.ax1.set_title("Network Performance Over Time")
        self.ax1.set_xlabel("Time (s)")
        self.ax1.set_ylabel("Bandwidth Usage (bytes/s)")
        self.ax2.set_ylabel("Packet Rate (packets/s) and Average Packet Size (bytes)")
        self.ax3.set_title("Packet Details Over Time")
        self.ax3.set_xlabel("Time (s)")
        self.ax3.set_ylabel("Packet Length")
        self.ax4.set_ylabel("Protocol")

        # Create a FigureCanvasTkAgg widget
        self.canvas = FigureCanvasTkAgg(self.figure, master=self.graph_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        # Data for plotting
        self.time_data = []
        self.packet_rate_data = []
        self.bandwidth_usage_data = []
        self.average_packet_size_data = []
        self.packet_length_data = []
        self.packet_protocol_data = []
        self.packet_source_data = []
        self.packet_destination_data = []
        self.packet_index_data = []

    def packet_callback(self, packet):
        # Check if the packet contains the IP layer
        if IP in packet:
            # Extract relevant information from the packet
            packet_data = {
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),  # Convert timestamp to string format
                'source': str(packet[IP].src),  # Access source IP address using IP.src
                'destination': str(packet[IP].dst),  # Access destination IP address using IP.dst
                'protocol': PROTOCOLS.get(packet[IP].proto, str(packet[IP].proto)),  # Access protocol using IP.proto and map to name
                'length': len(packet),
                'info': packet.summary()  # Summary of packet
            }

            # Put packet data in the queue for display
            self.queue.put(packet_data)

            # Store packet data in the packet list
            self.packets.append(packet_data)

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
        # Update the total packet count and data length
        self.packet_count += 1
        self.total_data_length += packet_data['length']

        # Calculate the time elapsed since the start
        current_time = datetime.now()
        elapsed_time = (current_time - self.start_time).total_seconds()

        if elapsed_time > 0:
            # Calculate packet rate (packets per second)
            packet_rate = self.packet_count / elapsed_time

            # Calculate bandwidth usage (bytes per second)
            bandwidth_usage = self.total_data_length / elapsed_time

            # Calculate average packet size
            average_packet_size = self.total_data_length / self.packet_count

            # Put the metrics in the queue to be processed by the main thread
            self.metrics_queue.put((packet_rate, bandwidth_usage, average_packet_size, elapsed_time, packet_data))

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

            try:
                # Get metrics from the metrics_queue
                packet_rate, bandwidth_usage, average_packet_size, elapsed_time, packet_data = self.metrics_queue.get_nowait()

                # Update the UI with these metrics
                self.packet_rate_label.config(text=f"Packet Rate: {packet_rate:.2f} packets/sec")
                self.bandwidth_usage_label.config(text=f"Bandwidth Usage: {bandwidth_usage:.2f} bytes/sec")

                # Update the graph data
                self.time_data.append(elapsed_time)
                self.packet_rate_data.append(packet_rate)
                self.bandwidth_usage_data.append(bandwidth_usage)
                self.average_packet_size_data.append(average_packet_size)
                self.packet_length_data.append(packet_data['length'])
                self.packet_protocol_data.append(packet_data['protocol'])
                self.packet_source_data.append(packet_data['source'])
                self.packet_destination_data.append(packet_data['destination'])
                self.packet_index_data.append(len(self.packet_index_data) + 1)

                self.update_graph()

            except Empty:
                # Metrics queue is empty, continue
                pass

            self.root.update_idletasks()
            self.root.update()

            # Introduce a delay to slow down the appearance of new data
            time.sleep(0.5)  # Adjust the delay time as needed (0.5 seconds in this example)

    def update_graph(self):
        self.ax1.clear()
        self.ax2.clear()
        self.ax3.clear()
        self.ax4.clear()

        self.ax1.plot(self.time_data, self.bandwidth_usage_data, label='Bandwidth Usage (bytes/s)', color='red')
        self.ax2.plot(self.time_data, self.packet_rate_data, label='Packet Rate (packets/s)', color='blue')
        self.ax2.plot(self.time_data, self.average_packet_size_data, label='Average Packet Size (bytes)', color='green')
        self.ax3.plot(self.time_data, self.packet_length_data, label='Packet Length', color='purple')
        self.ax4.plot(self.time_data, self.packet_protocol_data, label='Protocol', color='brown')

        self.ax1.set_title("Network Performance Over Time")
        self.ax1.set_xlabel("Time (s)")
        self.ax1.set_ylabel("Bandwidth Usage (bytes/s)")
        self.ax2.set_ylabel("Packet Rate (packets/s) and Average Packet Size (bytes)")
        self.ax3.set_title("Packet Details Over Time")
        self.ax3.set_xlabel("Time (s)")
        self.ax3.set_ylabel("Packet Length")
        self.ax4.set_ylabel("Protocol")

        self.ax1.legend(loc='upper left')
        self.ax2.legend(loc='upper right')
        self.ax3.legend(loc='upper left')
        self.ax4.legend(loc='upper right')

        self.canvas.draw()

    def display_packet(self, packet_data):
        index = len(self.packet_tree.get_children()) + 1
        self.packet_tree.insert("", "end", text=index, values=(
            packet_data['timestamp'],
            packet_data['source'],
            packet_data['destination'],
            packet_data['protocol'],
            packet_data['length'],
            packet_data['info']
        ))

    def apply_filter(self, event=None):
        filter_text = self.filter_text.get().lower().strip()
        self.packet_tree.delete(*self.packet_tree.get_children())

        # Parse the filter
        if "==" in filter_text:
            field, value = filter_text.split("==")
            field = field.strip()
            value = value.strip()

            filtered_packets = [
                pkt for pkt in self.packets
                if (field == "ip.src" and pkt['source'] == value) or
                   (field == "ip.dst" and pkt['destination'] == value) or
                   (field == "protocol" and pkt['protocol'].lower() == value.lower()) or
                   (field == "length" and str(pkt['length']) == value) or
                   (field == "timestamp" and value in pkt['timestamp'].lower()) or
                   (field == "info" and value in pkt['info'].lower())
            ]
        else:
            filtered_packets = [
                pkt for pkt in self.packets
                if filter_text in pkt['timestamp'].lower() or
                   filter_text in pkt['source'].lower() or
                   filter_text in pkt['destination'].lower() or
                   filter_text in pkt['protocol'].lower() or
                   filter_text in str(pkt['length']) or
                   filter_text in pkt['info'].lower()
            ]

        for packet in filtered_packets:
            self.display_packet(packet)

    def run(self):
        self.update_gui()


if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkMonitorController(root)
    app.run()
