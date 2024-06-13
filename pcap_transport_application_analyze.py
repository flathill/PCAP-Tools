# pcap_transport_application_analyze.py
#   Seiichirou Hiraoka <seiichirou.hiraoka@gmail.com> with ChatGPT 4o
#     Initial Version: 2024/06/13

import os
import sys
import pyshark
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.backends.backend_pdf import PdfPages
from tqdm import tqdm
import argparse
from datetime import datetime
import pytz

# コマンドライン引数の解析
parser = argparse.ArgumentParser(description='PCAP analysis script.')
parser.add_argument('--dir', type=str, default='pcap', help='PCAP files directory (default: pcap)')
parser.add_argument('--legend', action='store_true', help='Include legend in the output')
parser.add_argument('--interval', type=int, default=10, help='Time range interval in minutes (default: 10)')
args = parser.parse_args()

# 引数からPCAPファイルディレクトリと凡例の有無、タイムレンジを取得
pcap_dir = args.dir
include_legend = args.legend
time_interval = args.interval

# PDF出力用のファイル名（ディレクトリ名を付与、凡例の有無で変更）
file_suffix = f'_{time_interval}min_legend' if include_legend else f'_{time_interval}min'
pdf_output = f'transport_application_layer_packet_analysis_{os.path.basename(pcap_dir.rstrip("/"))}{file_suffix}.pdf'

print(f"Time range interval: {time_interval} minutes")
print(f"Analysis target directory: {pcap_dir}")
print(f"Legend: {'Enabled' if include_legend else 'Disabled'}")

# /etc/servicesからプロトコル情報を取得する関数
def load_services():
    services = {}
    with open('/etc/services') as f:
        for line in f:
            if line.startswith('#') or not line.strip():
                continue
            parts = line.split()
            if len(parts) >= 2:
                port_protocol = parts[1]
                service = parts[0]
                services[port_protocol] = service
    return services

# ポート番号からレンジ名を取得する関数
def get_port_range(port):
    port = int(port)
    port_ranges = {
        '1024-2047': range(1024, 2047),
        '2048-4095': range(2048, 4095),
        '4096-8191': range(4096, 8191),
        '8192-16383': range(8192, 16383),
        '16384-32767': range(16384, 32767),
        '32768-65535': range(32768, 65535)
    }
    for range_name, port_range in port_ranges.items():
        if port in port_range:
            return range_name
    return str(port)

# パケット解析とデータフレーム作成
def analyze_pcap(file_path, file_index, total_files, services):
    desc = f"Processing file {file_index}/{total_files}: {os.path.basename(file_path)}"
    capture = pyshark.FileCapture(file_path, use_json=True)
    records = []
    packet_count = 0
    start_time = datetime.now()
    
    for packet in tqdm(capture, desc=desc, unit='packets', leave=False):
        try:
            time_epoch = float(packet.sniff_timestamp)
            time_local = datetime.fromtimestamp(time_epoch)
            src_port = packet[packet.transport_layer].srcport
            dst_port = packet[packet.transport_layer].dstport
            src_port_range = get_port_range(src_port)
            dst_port_range = get_port_range(dst_port)
            protocol = f"{packet.transport_layer}/{src_port_range}" if src_port in services else f"{packet.transport_layer}/{dst_port_range}"
            application = services.get(f"{src_port}/{packet.transport_layer}", services.get(f"{dst_port}/{packet.transport_layer}", "Unknown"))
            records.append((time_local, protocol, application))
            packet_count += 1
        except AttributeError:
            continue

    end_time = datetime.now()
    capture.close()
    df = pd.DataFrame(records, columns=['timestamp', 'protocol', 'application'])
    duration = (end_time - start_time).total_seconds()
    packets_per_sec = packet_count / duration
    tqdm.write(f"{desc}: {packet_count} packets [{duration:.2f}s, {packets_per_sec:.2f} packets/s]")
    return df, packet_count

# 複数ファイルの解析
def analyze_multiple_pcaps(file_paths):
    all_data = pd.DataFrame()
    services = load_services()
    total_packet_count = 0

    for i, file_path in enumerate(file_paths, start=1):
        file_data, packet_count = analyze_pcap(file_path, i, len(file_paths), services)
        all_data = pd.concat([all_data, file_data])
        total_packet_count += packet_count

    print(f"Total packets: {total_packet_count}")
    return all_data

# ディレクトリ内のすべてのPCAPファイルを読み込んで解析
pcap_files = [os.path.join(pcap_dir, f) for f in os.listdir(pcap_dir) if f.endswith('.pcap')]
all_data = analyze_multiple_pcaps(pcap_files)

# タイムスタンプをタイムレンジ毎にグループ化
all_data['time_bin'] = pd.to_datetime(all_data['timestamp']).dt.floor(f'{time_interval}T')
grouped_data = all_data.groupby(['time_bin', 'protocol']).size().unstack(fill_value=0)

# プロトコル名を正規化する関数
def normalize_protocol(protocol, services):
    transport_layer, port_range = protocol.split('/')
    port_protocol = f"{port_range}/{transport_layer.lower()}"
    if port_protocol in services:
        normalized_name = f"{transport_layer}/{services[port_protocol]}"
    else:
        normalized_name = f"{transport_layer}/{port_range}"
    return normalized_name

services = load_services()
grouped_data.columns = [normalize_protocol(col, services) for col in grouped_data.columns]

# データをソートして件数の少ないものから順に積み上げる
grouped_data = grouped_data.reindex(grouped_data.sum().sort_values().index, axis=1)

# 色の設定
colors = plt.cm.tab20.colors

# 積み上げグラフを作成してPDFに保存
with PdfPages(pdf_output) as pdf:
    fig, ax = plt.subplots(figsize=(20, 10))
    bars = grouped_data.plot(kind='bar', stacked=True, ax=ax, color=colors, edgecolor='black')

    # 縦軸を対数スケールに設定
    ax.set_yscale('log')

    # 件数とプロトコル名をプロット
    for i, container in enumerate(bars.containers):
        protocol_name = grouped_data.columns[i]
        for bar in container:
            height = bar.get_height()
            if height > 0:
                label = f'{protocol_name}:{int(height)}' if not include_legend else f'{int(height)}'
                ax.text(
                    bar.get_x() + bar.get_width() / 2,
                    bar.get_y() + height / 2,
                    label,
                    ha='center',
                    va='center',
                    fontsize=6,  # フォントサイズを小さく設定
                    color='black'
                )

    ax.set_title('Packet Distribution Over Time')
    ax.set_xlabel('Time')
    ax.set_ylabel('Packet Count')
    ax.set_xticks(range(len(grouped_data.index)))
    ax.set_xticklabels([time_bin.strftime('%m/%d %H:%M') for time_bin in grouped_data.index], rotation=45, ha='right')

    if include_legend:
        handles = [mpatches.Patch(facecolor=colors[i % len(colors)], label=label) for i, label in enumerate(grouped_data.columns)]
        ax.legend(handles=handles, loc='center left', bbox_to_anchor=(1.0, 0.5))
    else:
        ax.legend().set_visible(False)

    pdf.savefig(fig, bbox_inches='tight')
    plt.close(fig)

print(f"PDF report has been generated: {pdf_output}")
