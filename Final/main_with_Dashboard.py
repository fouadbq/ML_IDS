from flask import Flask, render_template
import pandas as pd
import joblib
from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR, DNSRR, Raw
from scapy.layers.http import HTTPRequest, HTTPResponse

app = Flask(__name__)

# Load the model, scaler, and label encoder from the local directory
rf_classifier = joblib.load('path_to_local_directory/rf_classifier.pkl')
scaler = joblib.load('path_to_local_directory/scaler.pkl')
label_encoder = joblib.load('path_to_local_directory/label_encoder.pkl')

packet_details = []
predictions = []

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

    # (Same processing code as above)

    packet_details.append(packet_dict)

    if len(packet_details) >= 100:
        df = pd.DataFrame(packet_details)
        df = preprocess_data(df)
        preds = rf_classifier.predict(df)
        decoded_preds = label_encoder.inverse_transform(preds)
        predictions.extend(decoded_preds)
        packet_details.clear()

def preprocess_data(data):
    data = data.fillna(0)
    categorical_cols = data.select_dtypes(include=['object']).columns
    for col in categorical_cols:
        data[col] = data[col].astype(str)
        data[col] = label_encoder.transform(data[col])
    data = pd.DataFrame(scaler.transform(data), columns=data.columns)
    return data

@app.route('/')
def index():
    return render_template('index.html', predictions=predictions)

if __name__ == '__main__':
    sniff(prn=process_packet, count=0)  # Start sniffing in a separate thread or process
    app.run(debug=True, use_reloader=False)  # Set use_reloader=False to prevent reloading issues
