# pcap_network_analyze.ps1
#   Seiichirou Hiraoka <seiichirou.hiraoka@gmail.com> with ChatGPT 4o
#     Initial Version: 2024/06/13

import os
import pyshark
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
from datetime import datetime
from tqdm import tqdm
import argparse

# ネットワークレイヤープロトコルの定義
network_layer_protocols = ['IP', 'ARP', 'RARP', 'ICMP', 'CDP', 'DHCPV6', 'ICMPV6', 'MDNS', 'LLMNR', 'LLDP', 'IGMP', 'DATA']

# ファイル読み込みと解析
def analyze_pcap(file_path, file_index, total_files):
    desc = f"Processing file {file_index}/{total_files}: {os.path.basename(file_path)}"
    capture = pyshark.FileCapture(file_path, use_json=True)
    data = []
    for packet in tqdm(capture, desc=desc, unit='packets'):
        try:
            time_utc = datetime.fromtimestamp(float(packet.sniff_timestamp))
            found_protocol = False
            for layer in packet.layers:
                if layer.layer_name.upper() in network_layer_protocols:
                    data.append((time_utc, layer.layer_name.upper()))
                    found_protocol = True
                    break
            if not found_protocol:
                tqdm.write(f"Unexpected protocol found: {packet.layers[-1].layer_name.upper()}")
        except AttributeError:
            continue
    capture.close()
    return data

# 複数ファイルの解析
def analyze_multiple_pcaps(file_paths):
    all_data = []
    total_packet_count = 0
    total_files = len(file_paths)
    for index, file_path in enumerate(file_paths, start=1):
        data = analyze_pcap(file_path, index, total_files)
        all_data.extend(data)
        total_packet_count += len(data)
    print(f"Total packets: {total_packet_count}")
    return all_data

# タイムレンジ毎に集計
def aggregate_data(data, interval_minutes):
    df = pd.DataFrame(data, columns=['time', 'protocol'])
    df.set_index('time', inplace=True)
    start_time = df.index.min()
    end_time = df.index.max()

    intervals = pd.date_range(start=start_time, end=end_time, freq=f'{interval_minutes}T')
    grouped = df.groupby([pd.Grouper(freq=f'{interval_minutes}T'), 'protocol']).size().unstack().fillna(0)

    # 全体でのパケット数が少ない順にプロトコルを並べ替える
    protocol_order = grouped.sum().sort_values().index
    grouped = grouped[protocol_order]

    return grouped

# グラフ作成とPDF出力
def create_stackplot(df, pdf, show_legend):
    fig, ax = plt.subplots(figsize=(20, 10))
    bars = df.plot(kind='bar', stacked=True, ax=ax, edgecolor='black', logy=True)  # 縦軸を対数表示に設定
    ax.set_title('Network Layer Protocols over Time')
    ax.set_xlabel('Time')
    ax.set_ylabel('Packet Count')

    # X軸のフォーマットを設定
    new_labels = [label.strftime('%m/%d %H:%M') for label in df.index]
    ax.set_xticks(range(len(new_labels)))
    ax.set_xticklabels(new_labels, rotation=45, fontsize=8)

    # 各プロトコルの件数を表示
    for i, (time, row) in enumerate(df.iterrows()):
        cumulative_sum = row.cumsum()
        for protocol, count in row.items():
            if count > 0:
                y_position = cumulative_sum[protocol] - count / 2
                if show_legend:
                    ax.text(i, y_position, f"{int(count)}", ha='center', va='center', fontsize=6, color='black')
                else:
                    ax.text(i, y_position, f"{protocol}:{int(count)}", ha='center', va='center', fontsize=6, color='black')

    if show_legend:
        ax.legend(title='Protocol', bbox_to_anchor=(1.05, 1), loc='upper left')
    else:
        ax.get_legend().remove()

    pdf.savefig(fig)
    plt.close(fig)

# メイン処理
def main(pcap_directory, output_file, show_legend, interval_minutes):
    print(f"Time range interval: {interval_minutes} minutes")
    print(f"Analysis target directory: {pcap_directory}")
    print(f"Legend: {'Enabled' if show_legend else 'Disabled'}")

    pcap_files = sorted([os.path.join(pcap_directory, f) for f in os.listdir(pcap_directory) if f.endswith('.pcap')])
    data = analyze_multiple_pcaps(pcap_files)
    aggregated_data = aggregate_data(data, interval_minutes)

    with PdfPages(output_file) as pdf:
        create_stackplot(aggregated_data, pdf, show_legend)
    print(f"PDF generated: {output_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze PCAP files and generate a network layer protocol stack plot.")
    parser.add_argument("--dir", type=str, default="pcap", help="Directory containing the PCAP files.")
    parser.add_argument("--legend", action="store_true", help="Show legend on the plot.")
    parser.add_argument("--interval", type=int, default=10, help="Time interval for analysis in minutes.")
    args = parser.parse_args()

    pcap_directory = args.dir
    show_legend = args.legend
    interval_minutes = args.interval
    legend_suffix = "_legend" if show_legend else ""
    output_file = f"network_layer_packet_analysis_{os.path.basename(os.path.normpath(pcap_directory))}_{interval_minutes}min{legend_suffix}.pdf"

    main(pcap_directory, output_file, show_legend, interval_minutes)
