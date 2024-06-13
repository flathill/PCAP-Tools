# pcap_network_analyze.py
#   Seiichirou Hiraoka <seiichirou.hiraoka@gmail.com> with ChatGPT 4o
#     Initial Version: 2024/06/13

# ライブラリをインポート
import os
import pyshark
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
from datetime import datetime
from tqdm import tqdm
import argparse

# ネットワークレイヤープロトコルの定義
network_layer_protocols = ['IP', 'ARP', 'RARP', 'ICMP', 'CDP', 'DHCPV6', 'ICMPV6', 'MDNS', 'LLMNR', 'LLDP', 'IGMP', 'DATA', 'IPV6', 'OSPF', 'BGP', 'EIGRP', 'SCTP', 'GRE', 'VXLAN', 'MPLS', 'STP', 'PPP', 'L2TP', 'PPTP']

# ファイル読み込みと解析
def analyze_pcap(file_path, file_index, total_files):
    # ファイルの読み込み
    desc = f"Processing file {file_index}/{total_files}: {os.path.basename(file_path)}"
    # JSON形式で読み込む
    capture = pyshark.FileCapture(file_path, use_json=True)
    # パケットごとに解析
    data = []
    # プログレスバーを表示
    for packet in tqdm(capture, desc=desc, unit='packets'):
        try:
            # タイムスタンプを取得
            systemtime = datetime.fromtimestamp(float(packet.sniff_timestamp))
            # プロトコルが見つからない場合はスキップ
            found_protocol = False
            # レイヤーごとにプロトコルを抽出
            for layer in packet.layers:
                # ネットワークレイヤープロトコルのみを抽出
                if layer.layer_name.upper() in network_layer_protocols:
                    # プロトコルとタイムスタンプを保存
                    data.append((systemtime, layer.layer_name.upper()))
                    found_protocol = True
                    # プロトコルが見つかったらループを抜ける
                    break
            # プロトコルが見つからない場合は警告を表示
            if not found_protocol:
                tqdm.write(f"Unexpected protocol found: {packet.layers[-1].layer_name.upper()}")
        # 属性エラーが発生した場合はスキップ
        except AttributeError:
            # スキップ
            continue
    # ファイルを閉じる
    capture.close()
    # データを返す
    return data

# 複数ファイルの解析
def analyze_multiple_pcaps(file_paths):
    # データを格納するリストを作成
    all_data = []
    # 合計パケット数を0に設定
    total_packet_count = 0
    # 解析対象ファイル数を取得
    total_files = len(file_paths)
    # ファイルごとに解析
    for index, file_path in enumerate(file_paths, start=1):
        # パケットを解析
        data = analyze_pcap(file_path, index, total_files)
        # データを追加
        all_data.extend(data)
        # パケット数をカウント
        total_packet_count += len(data)
    # パケット数を表示
    print(f"Total packets: {total_packet_count}")
    # データを返す
    return all_data

# タイムレンジ毎に集計
def aggregate_data(data, interval_minutes):
    # データをデータフレームに変換
    df = pd.DataFrame(data, columns=['time', 'protocol'])
    # インデックスをタイムスタンプに設定
    df.set_index('time', inplace=True)
    # 開始時刻を取得
    start_time = df.index.min()
    # 終了時刻を取得
    end_time = df.index.max()

    # 指定した間隔で集計
    intervals = pd.date_range(start=start_time, end=end_time, freq=f'{interval_minutes}T')
    # グループ化して集計
    grouped = df.groupby([pd.Grouper(freq=f'{interval_minutes}T'), 'protocol']).size().unstack().fillna(0)

    # 全体でのパケット数が少ない順にプロトコルを並べ替える
    protocol_order = grouped.sum().sort_values().index
    # プロトコルの順序を変更
    grouped = grouped[protocol_order]

    # 集計結果を返す
    return grouped

# グラフ作成とPDF出力
def create_stackplot(df, pdf, show_legend):
    # グラフを作成
    fig, ax = plt.subplots(figsize=(20, 10))
    # 積み上げ棒グラフを作成
    bars = df.plot(kind='bar', stacked=True, ax=ax, edgecolor='black', logy=True)  # 縦軸を対数表示に設定
    # タイトルを設定
    ax.set_title('Network Layer Protocols over Time')
    # X軸のラベルを設定
    ax.set_xlabel('Time')
    # Y軸のラベルを設定
    ax.set_ylabel('Packet Count')

    # X軸のフォーマットを設定
    new_labels = [label.strftime('%m/%d %H:%M') for label in df.index]
    # X軸の目盛りを設定
    ax.set_xticks(range(len(new_labels)))
    # X軸のラベルを設定
    ax.set_xticklabels(new_labels, rotation=45, fontsize=8)

    # 各プロトコルの件数を表示
    for i, (time, row) in enumerate(df.iterrows()):
        # 累積和を計算
        cumulative_sum = row.cumsum()
        # プロトコルごとに件数を表示
        for protocol, count in row.items():
            # プロトコルの件数が0より大きい場合
            if count > 0:
                # プロトコルの位置を計算
                y_position = cumulative_sum[protocol] - count / 2
                # 凡例を表示する場合
                if show_legend:
                    # 件数を表示
                    ax.text(i, y_position, f"{int(count)}", ha='center', va='center', fontsize=6, color='black')
                # 凡例を表示しない場合
                else:
                    # プロトコル名と件数を表示
                    ax.text(i, y_position, f"{protocol}:{int(count)}", ha='center', va='center', fontsize=6, color='black')

    # 凡例を表示する場合
    if show_legend:
        # 凡例を表示
        ax.legend(title='Protocol', bbox_to_anchor=(1.05, 1), loc='upper left')
    # 凡例を表示しない場合
    else:
        # 凡例を削除
        ax.get_legend().remove()

    # PDFにグラフを保存
    pdf.savefig(fig)
    # グラフを閉じる
    plt.close(fig)

# メイン処理
def main(pcap_directory, output_file, show_legend, interval_minutes):
    # 時間範囲の間隔を表示
    print(f"Time range interval: {interval_minutes} minutes")
    # 解析対象ディレクトリを表示
    print(f"Analysis target directory: {pcap_directory}")
    # 凡例の表示状態を表示
    print(f"Legend: {'Enabled' if show_legend else 'Disabled'}")

    # PCAPファイルを取得
    pcap_files = sorted([os.path.join(pcap_directory, f) for f in os.listdir(pcap_directory) if f.endswith('.pcap')])
    # PCAPファイルを解析
    data = analyze_multiple_pcaps(pcap_files)
    # データを集計
    aggregated_data = aggregate_data(data, interval_minutes)

    # PDFファイルを作成
    with PdfPages(output_file) as pdf:
        # スタックプロットを作成
        create_stackplot(aggregated_data, pdf, show_legend)
    # PDFファイルのパスを表示
    print(f"PDF generated: {output_file}")

# メイン処理を実行
if __name__ == "__main__":
    # コマンドライン引数を解析
    parser = argparse.ArgumentParser(description="Analyze PCAP files and generate a network layer protocol stack plot.")
    # ディレクトリを指定
    parser.add_argument("--dir", type=str, default="pcap", help="Directory containing the PCAP files.")
    # 凡例の表示
    parser.add_argument("--legend", action="store_true", help="Show legend on the plot.")
    # 時間間隔を指定
    parser.add_argument("--interval", type=int, default=10, help="Time interval for analysis in minutes.")
    # コマンドライン引数を取得
    args = parser.parse_args()

    # ディレクトリを設定
    pcap_directory = args.dir
    # 凡例の表示を設定
    show_legend = args.legend
    # インターバルを設定
    interval_minutes = args.interval
    # 凡例の表示状態に応じて凡例のサフィックスを設定
    legend_suffix = "_legend" if show_legend else ""
    # 出力ファイル名を設定
    output_file = f"network_layer_packet_analysis_{os.path.basename(os.path.normpath(pcap_directory))}_{interval_minutes}min{legend_suffix}.pdf"

    # メイン処理を実行
    main(pcap_directory, output_file, show_legend, interval_minutes)