import logging
from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR, DNSRR, Raw
from scapy.layers.http import HTTPRequest, HTTPResponse
import pandas as pd
import joblib

# Set up logging
logging.basicConfig(filename='intrusion_detection.log', level=logging.INFO, format='%(asctime)s - %(message)s')
root ='C:/Users/HP_User/Desktop/School/NetSec/Final/label_encoder.pkl'
# Load the model, scaler, and label encoder from the local directory
rf_classifier = joblib.load('C:/Users/HP_User/Desktop/School/NetSec/Final/rf_classifier.pkl')
scaler = joblib.load('C:/Users/HP_User/Desktop/School/NetSec/Final/scaler.pkl')
label_encoder = joblib.load('C:/Users/HP_User/Desktop/School/NetSec/Final/label_encoder.pkl')

# List to store packet details
packet_details = []

# Function to process each packet
def process_packet(packet):
    packet_dict = {
        'eth_src': None, 'eth_dst': None, 'eth_type': None,
        'ip_version': None, 'ip_ihl': None, 'ip_tos': None, 'ip_len': None, 'ip_id': None, 'ip_flags': None, 'ip_frag': None, 'ip_ttl': None, 'ip_proto': None, 'ip_chksum': None, 'ip_src': None, 'ip_dst': None, 'ip_options': None,
        'tcp_sport': None, 'tcp_dport': None, 'tcp_seq': None, 'tcp_ack': None, 'tcp_dataofs': None, 'tcp_reserved': None, 'tcp_flags': None, 'tcp_window': None, 'tcp_chksum': None, 'tcp_urgptr': None, 'tcp_options': None,
        'tcp_flag_fin': None, 'tcp_flag_syn': None, 'tcp_flag_rst': None, 'tcp_flag_psh': None, 'tcp_flag_ack': None, 'tcp_flag_urg': None, 'tcp_flag_ece': None, 'tcp_flag_cwr': None, 'tcp_flag_ns': None,
        'udp_sport': None, 'udp_dport': None, 'udp_len': None, 'udp_chksum': None,
        'icmp_type': None, 'icmp_code': None, 'icmp_chksum': None, 'icmp_id': None, 'icmp_seq': None,
        'arp_hwtype': None, 'arp_ptype': None, 'arp_hwlen': None, 'arp_plen': None, 'arp_op': None, 'arp_hwsrc': None, 'arp_psrc': None, 'arp_hwdst': None, 'arp_pdst': None,
        'dns_id': None, 'dns_qr': None, 'dns_opcode': None, 'dns_aa': None, 'dns_tc': None, 'dns_rd': None, 'dns_ra': None, 'dns_z': None, 'dns_ad': None, 'dns_cd': None, 'dns_rcode': None, 'dns_qdcount': None, 'dns_ancount': None, 'dns_nscount': None, 'dns_arcount': None,
        'dns_qname': None, 'dns_qtype': None, 'dns_qclass': None, 'dns_rrname': None, 'dns_rrtype': None, 'dns_rrclass': None, 'dns_rrttl': None, 'dns_rdata': None,
        'http_method': None, 'http_host': None, 'http_path': None, 'http_user_agent': None, 'http_accept': None, 'http_accept_language': None, 'http_accept_encoding': None, 'http_connection': None,
        'http_status_code': None, 'http_server': None, 'http_content_type': None,
        'raw_load': None,
        'time': packet.time
    }

    # Capture Ethernet layer details
    if packet.haslayer(Ether):
        eth_layer = packet.getlayer(Ether)
        packet_dict['eth_src'] = eth_layer.src
        packet_dict['eth_dst'] = eth_layer.dst
        packet_dict['eth_type'] = eth_layer.type

    # Capture IP layer details
    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        packet_dict['ip_version'] = ip_layer.version
        packet_dict['ip_ihl'] = ip_layer.ihl
        packet_dict['ip_tos'] = ip_layer.tos
        packet_dict['ip_len'] = ip_layer.len
        packet_dict['ip_id'] = ip_layer.id
        packet_dict['ip_flags'] = ip_layer.flags
        packet_dict['ip_frag'] = ip_layer.frag
        packet_dict['ip_ttl'] = ip_layer.ttl
        packet_dict['ip_proto'] = ip_layer.proto
        packet_dict['ip_chksum'] = ip_layer.chksum
        packet_dict['ip_src'] = ip_layer.src
        packet_dict['ip_dst'] = ip_layer.dst
        packet_dict['ip_options'] = ip_layer.options

    # Capture TCP layer details
    if packet.haslayer(TCP):
        tcp_layer = packet.getlayer(TCP)
        packet_dict['tcp_sport'] = tcp_layer.sport
        packet_dict['tcp_dport'] = tcp_layer.dport
        packet_dict['tcp_seq'] = tcp_layer.seq
        packet_dict['tcp_ack'] = tcp_layer.ack
        packet_dict['tcp_dataofs'] = tcp_layer.dataofs
        packet_dict['tcp_reserved'] = tcp_layer.reserved
        packet_dict['tcp_flags'] = tcp_layer.flags
        packet_dict['tcp_window'] = tcp_layer.window
        packet_dict['tcp_chksum'] = tcp_layer.chksum
        packet_dict['tcp_urgptr'] = tcp_layer.urgptr
        packet_dict['tcp_options'] = tcp_layer.options

        # Break down TCP flags
        flags = {
            'tcp_flag_fin': tcp_layer.flags & 0x01,
            'tcp_flag_syn': (tcp_layer.flags >> 1) & 0x01,
            'tcp_flag_rst': (tcp_layer.flags >> 2) & 0x01,
            'tcp_flag_psh': (tcp_layer.flags >> 3) & 0x01,
            'tcp_flag_ack': (tcp_layer.flags >> 4) & 0x01,
            'tcp_flag_urg': (tcp_layer.flags >> 5) & 0x01,
            'tcp_flag_ece': (tcp_layer.flags >> 6) & 0x01,
            'tcp_flag_cwr': (tcp_layer.flags >> 7) & 0x01,
            'tcp_flag_ns': (tcp_layer.flags >> 8) & 0x01
        }
        packet_dict.update(flags)

    # Capture UDP layer details
    if packet.haslayer(UDP):
        udp_layer = packet.getlayer(UDP)
        packet_dict['udp_sport'] = udp_layer.sport
        packet_dict['udp_dport'] = udp_layer.dport
        packet_dict['udp_len'] = udp_layer.len
        packet_dict['udp_chksum'] = udp_layer.chksum

    # Capture ICMP layer details
    if packet.haslayer(ICMP):
        icmp_layer = packet.getlayer(ICMP)
        packet_dict['icmp_type'] = icmp_layer.type
        packet_dict['icmp_code'] = icmp_layer.code
        packet_dict['icmp_chksum'] = icmp_layer.chksum
        packet_dict['icmp_id'] = icmp_layer.id
        packet_dict['icmp_seq'] = icmp_layer.seq

    # Capture ARP layer details
    if packet.haslayer(ARP):
        arp_layer = packet.getlayer(ARP)
        packet_dict['arp_hwtype'] = arp_layer.hwtype
        packet_dict['arp_ptype'] = arp_layer.ptype
        packet_dict['arp_hwlen'] = arp_layer.hwlen
        packet_dict['arp_plen'] = arp_layer.plen
        packet_dict['arp_op'] = arp_layer.op
        packet_dict['arp_hwsrc'] = arp_layer.hwsrc
        packet_dict['arp_psrc'] = arp_layer.psrc
        packet_dict['arp_hwdst'] = arp_layer.hwdst
        packet_dict['arp_pdst'] = arp_layer.pdst

    # Capture DNS layer details
    if packet.haslayer(DNS):
        dns_layer = packet.getlayer(DNS)
        packet_dict['dns_id'] = dns_layer.id
        packet_dict['dns_qr'] = dns_layer.qr
        packet_dict['dns_opcode'] = dns_layer.opcode
        packet_dict['dns_aa'] = dns_layer.aa
        packet_dict['dns_tc'] = dns_layer.tc
        packet_dict['dns_rd'] = dns_layer.rd
        packet_dict['dns_ra'] = dns_layer.ra
        packet_dict['dns_z'] = dns_layer.z
        packet_dict['dns_ad'] = dns_layer.ad
        packet_dict['dns_cd'] = dns_layer.cd
        packet_dict['dns_rcode']= dns_layer.rcode
        packet_dict['dns_qdcount'] = dns_layer.qdcount
        packet_dict['dns_ancount'] = dns_layer.ancount
        packet_dict['dns_nscount'] = dns_layer.nscount
        packet_dict['dns_arcount'] = dns_layer.arcount

        if packet.haslayer(DNSQR):
            dnsqr_layer = packet.getlayer(DNSQR)
            packet_dict['dns_qname'] = dnsqr_layer.qname
            packet_dict['dns_qtype'] = dnsqr_layer.qtype
            packet_dict['dns_qclass'] = dnsqr_layer.qclass

        if packet.haslayer(DNSRR):
            dnsrr_layer = packet.getlayer(DNSRR)
            packet_dict['dns_rrname'] = dnsrr_layer.rrname
            packet_dict['dns_rrtype'] = dnsrr_layer.type
            packet_dict['dns_rrclass'] = dnsrr_layer.rclass
            packet_dict['dns_rrttl'] = dnsrr_layer.ttl
            packet_dict['dns_rdata'] = dnsrr_layer.rdata

    # Capture HTTP layer details
    if packet.haslayer(HTTPRequest):
        http_layer = packet.getlayer(HTTPRequest)
        packet_dict['http_method'] = http_layer.Method.decode(errors='ignore')
        packet_dict['http_host'] = http_layer.Host.decode(errors='ignore')
        packet_dict['http_path'] = http_layer.Path.decode(errors='ignore')
        packet_dict['http_user_agent'] = http_layer.User_Agent.decode(errors='ignore')
        packet_dict['http_accept'] = http_layer.Accept.decode(errors='ignore')
        packet_dict['http_accept_language'] = http_layer.Accept_Language.decode(errors='ignore')
        packet_dict['http_accept_encoding'] = http_layer.Accept_Encoding.decode(errors='ignore')
        packet_dict['http_connection'] = http_layer.Connection.decode(errors='ignore')

    if packet.haslayer(HTTPResponse):
        http_layer = packet.getlayer(HTTPResponse)
        packet_dict['http_status_code'] = http_layer.Status_Code.decode(errors='ignore')
        packet_dict['http_server'] = http_layer.Server.decode(errors='ignore')
        packet_dict['http_content_type'] = http_layer.Content_Type.decode(errors='ignore')

    # Capture Raw layer (payload) details
    if packet.haslayer(Raw):
        raw_layer = packet.getlayer(Raw)
        packet_dict['raw_load'] = raw_layer.load.decode(errors='ignore')

    # Capture packet time
    packet_dict['time'] = packet.time

    # Append packet details to the list
    packet_details.append(packet_dict)

    # Process and predict the traffic type
    if len(packet_details) >= 100:  # Process after every 100 packets
        df = pd.DataFrame(packet_details)
        df = preprocess_data(df)
        predictions = rf_classifier.predict(df)
        decoded_predictions = label_encoder.inverse_transform(predictions)
        
        # Log the predictions
        for prediction in decoded_predictions:
            logging.info(f'Prediction: {prediction}')
        
        print(decoded_predictions)  # Optional: also print to console
        packet_details.clear()  # Clear the list for the next batch

# Function to preprocess the data
def preprocess_data(data):
    # Handle missing values
    data = data.fillna(0)
    
    # Encode categorical variables
    categorical_cols = data.select_dtypes(include=['object']).columns
    for col in categorical_cols:
        data[col] = data[col].astype(str)
        data[col] = label_encoder.transform(data[col])
    
    # Normalize/Standardize the features
    data = pd.DataFrame(scaler.transform(data), columns=data.columns)
    return data

# Start sniffing the network traffic
sniff(prn=process_packet, count=0)  # Set count=0 to sniff indefinitely
