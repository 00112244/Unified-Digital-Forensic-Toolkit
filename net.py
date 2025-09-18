from dash import dcc, html, dash_table
from dash.dependencies import Input, Output, State
import scapy.all as scapy
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import dash


# Initialize Dash app
app = dash.Dash(__name__)

# Configuration variables
interface = "WiFi"
max_packets = 1000
captured_packets = []
traffic_data = []
last_selected_packet_info = None

# Function to capture packets using Scapy
def capture_packets():
    packet = scapy.sniff(iface=interface, count=1)[0]
    captured_packets.append(packet)

    # Maintain a maximum number of captured packets
    if len(captured_packets) > max_packets:
        captured_packets.pop(0)

# Function to map protocol numbers to names
def map_protocol(protocol_number):
    protocol_mapping = {1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 41: "IPv6", 47: "GRE", 50: "ESP", 51: "AH", 89: "OSPF", 132: "SCTP"}
    return protocol_mapping.get(protocol_number, str(protocol_number))

# Function to extract details from a packet for display
def extract_packet_details(packet):
    return {'frame_details': str(packet), 'packet_list_pane': str(packet.summary()), 'packet_bytes_pane': packet.show(dump=True), 'tree_view': str(packet.show(dump=True))}

# Function to extract relevant features from a packet
def extract_features(packet):
    try:
        if packet.haslayer(scapy.IP):
            src_ip, dst_ip, protocol = packet[scapy.IP].src, packet[scapy.IP].dst, map_protocol(packet[scapy.IP].proto)
            return {'src_ip': src_ip, 'dst_ip': dst_ip, 'protocol': protocol, 'length': len(packet), 'timestamp': packet.time, 'payload': str(packet.payload), 'info': packet.summary()}
        else:
            return None
    except AttributeError as e:
        return None

# NetPulse Analyzer Layout
app.layout = html.Div([
    dcc.Interval(id='interval-component', interval=1*1000, n_intervals=0),
    html.H1("Real-Time Packet Capture Analysis"),
    dash_table.DataTable(
        id='packet-table',
        columns=[
            {'name': 'Packet Number', 'id': 'packet_number'},
            {'name': 'Source IP', 'id': 'src_ip'},
            {'name': 'Destination IP', 'id': 'dst_ip'},
            {'name': 'Protocol', 'id': 'protocol'},
            {'name': 'Length', 'id': 'length'},
            {'name': 'Timestamp', 'id': 'timestamp'},
            {'name': 'Info', 'id': 'info'},
        ],
        data=[],
        row_selectable='single',
        selected_rows=[],
        style_table={'height': '300px', 'overflowY': 'auto'}
    ),
    html.Div(id='selected-packet-info', style={'whiteSpace': 'pre-line'}),
    html.Div(id='total-traffic'),
    dcc.Graph(id='protocol-pie-chart'),
    dcc.Graph(id='traffic-trend-chart'),
])

# Update Data and Charts Callback
@app.callback(
    [Output('packet-table', 'data'), Output('packet-table', 'selected_rows'), Output('total-traffic', 'children'),
     Output('protocol-pie-chart', 'figure'), Output('traffic-trend-chart', 'figure'), Output('selected-packet-info', 'children')],
    [Input('interval-component', 'n_intervals')], [State('packet-table', 'selected_rows')]
)
def update_data_and_charts(n, selected_rows):
    capture_packets()

    table_data, total_traffic = [], 0
    for i, packet in enumerate(captured_packets):
        features = extract_features(packet)
        if features:
            row = {'packet_number': i + 1, 'src_ip': features['src_ip'], 'dst_ip': features['dst_ip'], 'protocol': features['protocol'], 'length': features['length'], 'timestamp': features['timestamp'], 'info': features['info']}
            table_data.append(row)
            total_traffic += features['length']

    total_traffic_mb = round(total_traffic / (1024 * 1024), 2)
    total_traffic_text = f"Total Traffic: {total_traffic_mb} MB"

    global traffic_data
    traffic_data = pd.DataFrame(table_data)

    protocol_counts = traffic_data['protocol'].value_counts()
    pie_chart = px.pie(protocol_counts, names=protocol_counts.index, title='Traffic Distribution by Protocols')

    timestamps, traffic_lengths = traffic_data['timestamp'], traffic_data['length']
    bar_chart = go.Figure()
    bar_chart.add_trace(go.Bar(x=timestamps, y=traffic_lengths, name='Traffic Trend'))
    bar_chart.update_layout(title='Traffic Trend Over Time', xaxis_title='Timestamp', yaxis_title='Traffic Length (bytes)')

    selected_packet_info = None
    if not traffic_data.empty and selected_rows:
        selected_packet_number = selected_rows[0] + 1
        if 1 <= selected_packet_number <= len(captured_packets):
            selected_packet = captured_packets[selected_packet_number - 1]
            packet_details = extract_packet_details(selected_packet)

            selected_packet_info = [
                html.H3(f"Details for Packet {selected_packet_number}"),
                html.Div([html.H4("Frame Details"), dcc.Textarea(value=packet_details['frame_details'], readOnly=True)]),
                html.Div([html.H4("Packet List Pane"), dcc.Textarea(value=packet_details['packet_list_pane'], readOnly=True)]),
                html.Div([html.H4("Packet Bytes Pane"), dcc.Textarea(value=packet_details['packet_bytes_pane'], readOnly=True)]),
                html.Div([html.H4("Tree View"), dcc.Textarea(value=packet_details['tree_view'], readOnly=True)]),
            ]
            global last_selected_packet_info
            last_selected_packet_info = selected_packet_info

    return table_data, [], total_traffic_text, pie_chart, bar_chart, last_selected_packet_info

# Run the app if executed directly
if __name__ == '__main__':
    app.run_server(debug=True)
