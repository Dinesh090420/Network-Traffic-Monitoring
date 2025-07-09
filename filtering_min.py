import pyshark
import pandas as pd
import matplotlib.pyplot as plt
from collections import Counter
from datetime import datetime

# Define the path to your capture file
capture_file = '/Users/garbhapudinesh/Desktop/OSPROJECT/wireshark packets.pcapng'

time_counter = Counter()

# Open the capture file
cap = pyshark.FileCapture(capture_file, display_filter='ip')

# Count packets per minute based on timestamp
for pkt in cap:
    try:
        timestamp = float(pkt.sniff_timestamp)
        time_obj = datetime.fromtimestamp(timestamp)
        minute_key = time_obj.strftime('%Y-%m-%d %H:%M')  # group by minute
        time_counter[minute_key] += 1
    except Exception:
        continue

# Convert to DataFrame
df_time = pd.DataFrame(time_counter.items(), columns=['Time', 'Packet_Count'])
df_time.sort_values(by='Time', inplace=True)

# Plot
plt.figure(figsize=(14, 6))
plt.plot(df_time['Time'], df_time['Packet_Count'], marker='o')
plt.xticks(rotation=45)
plt.title('Packet Count Over Time')
plt.xlabel('Time (per minute)')
plt.ylabel('Packet Count')
plt.tight_layout()
plt.savefig('traffic_over_time.png')
plt.show()
