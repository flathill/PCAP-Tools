# pcap_transport_application_analyze.py
#   Seiichirou Hiraoka <seiichirou.hiraoka@gmail.com> with ChatGPT 4o
#     Initial Version: 2024/06/13

# ライブラリをインポート
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

# サービス名をロード
def load_services():
    # サービス名を格納する辞書を作成
    services = {}
    # サービス名を/etc/servicesから読み込む
    with open('/etc/services') as f:
        # ファイルを1行ずつ読み込む
        for line in f:
            # コメント行や空行はスキップ
            if line.startswith('#') or not line.strip():
                # 次の行へ
                continue
            # 行をスペースで分割
            parts = line.split()
            # ポート番号とプロトコルがある場合
            if len(parts) >= 2:
                # ポート番号とプロトコルを取得
                port_protocol = parts[1]
                # サービス名を取得
                service = parts[0]
                # ポート番号とプロトコルをキーとしてサービス名を格納
                services[port_protocol] = service
    # サービス名を返す
    return services

# ポート番号の範囲を取得
def get_port_range(port):
    # ポート番号を整数に変換
    port = int(port)
    # ポート番号の範囲を定義
    port_ranges = {
        '1024-2047': range(1024, 2047),
        '2048-4095': range(2048, 4095),
        '4096-8191': range(4096, 8191),
        '8192-16383': range(8192, 16383),
        '16384-32767': range(16384, 32767),
        '32768-65535': range(32768, 65535)
    }
    # ポート番号が範囲に含まれる場合は範囲名を返す
    for range_name, port_range in port_ranges.items():
        # ポート番号が範囲に含まれる場合
        if port in port_range:
            # 範囲名を返す
            return range_name
    # 範囲に含まれない場合はポート番号を文字列に変換して返す
    return str(port)

# PCAPファイルを解析
def analyze_pcap(file_path, file_index, total_files, services):
    # ファイルの読み込み
    desc = f"Processing file {file_index}/{total_files}: {os.path.basename(file_path)}"
    # JSON形式で読み込む
    capture = pyshark.FileCapture(file_path, use_json=True)
    # パケットごとに解析
    records = []
    # パケット数をカウント
    packet_count = 0
    # 開始時間を取得
    start_time = datetime.now()
    # プログレスバーを表示
    for packet in tqdm(capture, desc=desc, unit='packets', leave=False):
        try:
            # タイムスタンプを取得
            time_epoch = float(packet.sniff_timestamp)
            # タイムスタンプをローカル時間に変換
            time_local = datetime.fromtimestamp(time_epoch)
            # 送信元ポートを取得
            src_port = packet[packet.transport_layer].srcport
            # 宛先ポートを取得
            dst_port = packet[packet.transport_layer].dstport
            # 送信元ポートの範囲を取得
            src_port_range = get_port_range(src_port)
            # 宛先ポートの範囲を取得
            dst_port_range = get_port_range(dst_port)
            # プロトコルを取得
            protocol = f"{packet.transport_layer}/{src_port_range}" if src_port in services else f"{packet.transport_layer}/{dst_port_range}"
            # アプリケーションを取得
            application = services.get(f"{src_port}/{packet.transport_layer}", services.get(f"{dst_port}/{packet.transport_layer}", "Unknown"))
            # レコードを追加
            records.append((time_local, protocol, application))
            # パケット数をカウント
            packet_count += 1
        # 属性エラーが発生した場合はスキップ
        except AttributeError:
            continue
    # 終了時間を取得
    end_time = datetime.now()
    # ファイルを閉じる
    capture.close()
    # データフレームを作成
    df = pd.DataFrame(records, columns=['timestamp', 'protocol', 'application'])
    # 処理時間を計算
    duration = (end_time - start_time).total_seconds()
    # パケット数を計算
    packets_per_sec = packet_count / duration
    # パケット数をカウント
    packet_count = 0
    # 開始時間を取得
    start_time = datetime.now()
    
    # プログレスバーを表示    
    for packet in tqdm(capture, desc=desc, unit='packets', leave=False):
        try:
            # タイムスタンプを取得
            time_epoch = float(packet.sniff_timestamp)
            # タイムスタンプをローカル時間に変換
            time_local = datetime.fromtimestamp(time_epoch)
            # 送信元ポートを取得
            src_port = packet[packet.transport_layer].srcport
            # 宛先ポートを取得
            dst_port = packet[packet.transport_layer].dstport
            # 送信元ポートの範囲を取得
            src_port_range = get_port_range(src_port)
            # 宛先ポートの範囲を取得
            dst_port_range = get_port_range(dst_port)
            # プロトコルを取得
            protocol = f"{packet.transport_layer}/{src_port_range}" if src_port in services else f"{packet.transport_layer}/{dst_port_range}"
            # アプリケーションを取得
            application = services.get(f"{src_port}/{packet.transport_layer}", services.get(f"{dst_port}/{packet.transport_layer}", "Unknown"))
            # レコードを追加
            records.append((time_local, protocol, application))
            # パケット数をカウント
            packet_count += 1
        # 属性エラーが発生した場合はスキップ
        except AttributeError:
            # 次のパケットへ
            continue

    # 終了時間を取得
    end_time = datetime.now()
    # ファイルを閉じる
    capture.close()
    # データフレームを作成
    df = pd.DataFrame(records, columns=['timestamp', 'protocol', 'application'])
    # 処理時間を計算
    duration = (end_time - start_time).total_seconds()
    # パケット数を計算
    packets_per_sec = packet_count / duration
    # ログを出力
    tqdm.write(f"{desc}: {packet_count} packets [{duration:.2f}s, {packets_per_sec:.2f} packets/s]")
    # データフレームとパケット数を返す
    return df, packet_count

# 複数ファイルの解析
def analyze_multiple_pcaps(file_paths):
    # データを格納するデータフレームを作成
    all_data = pd.DataFrame()
    # サービス名をロード
    services = load_services()
    # パケット数をカウント
    total_packet_count = 0

    # ファイルごとに解析
    for i, file_path in enumerate(file_paths, start=1):
        # PCAPファイルを解析
        file_data, packet_count = analyze_pcap(file_path, i, len(file_paths), services)
        # データを追加
        all_data = pd.concat([all_data, file_data])
        # パケット数をカウント
        total_packet_count += packet_count

    # パケット数を表示
    print(f"Total packets: {total_packet_count}")
    # データを返す
    return all_data

# プロトコル名を正規化
def normalize_protocol(protocol, services):
    # トランスポートレイヤーとポート番号を取得
    transport_layer, port_range = protocol.split('/')
    # ポート番号とトランスポートレイヤーを結合
    port_protocol = f"{port_range}/{transport_layer.lower()}"
    # サービス名がある場合はサービス名を返す
    if port_protocol in services:
        # サービス名を返す
        normalized_name = f"{transport_layer}/{services[port_protocol]}"
    # サービス名がない場合はポート番号を返す
    else:
        # ポート番号を返す
        normalized_name = f"{transport_layer}/{port_range}"
    # 正規化したプロトコル名を返す
    return normalized_name

# メイン関数
def main():
    # コマンドライン引数の解析
    parser = argparse.ArgumentParser(description='PCAP analysis script.')
    # ディレクトリの指定
    parser.add_argument('--dir', type=str, default='pcap', help='PCAP files directory (default: pcap)')
    # 凡例の有無
    parser.add_argument('--legend', action='store_true', help='Include legend in the output')
    # タイムレンジの指定
    parser.add_argument('--interval', type=int, default=10, help='Time range interval in minutes (default: 10)')
    # 引数を解析
    args = parser.parse_args()

    # ディレクトリを取得
    pcap_dir = args.dir
    # 凡例の有無を取得
    include_legend = args.legend
    # タイムレンジを取得
    time_interval = args.interval

    # PDF出力用のファイル名（ディレクトリ名を付与、凡例の有無で変更）
    file_suffix = f'_{time_interval}min_legend' if include_legend else f'_{time_interval}min'
    # PDFファイル名を設定
    pdf_output = f'transport_application_layer_packet_analysis_{os.path.basename(pcap_dir.rstrip("/"))}{file_suffix}.pdf'

    # メッセージを表示
    print(f"Time range interval: {time_interval} minutes")
    print(f"Analysis target directory: {pcap_dir}")
    print(f"Legend: {'Enabled' if include_legend else 'Disabled'}")

    # ディレクトリ内のすべてのPCAPファイルを読み込んで解析
    pcap_files = [os.path.join(pcap_dir, f) for f in os.listdir(pcap_dir) if f.endswith('.pcap')]
    # 複数のPCAPファイルを解析
    all_data = analyze_multiple_pcaps(pcap_files)

    # タイムスタンプをタイムレンジ毎にグループ化
    all_data['time_bin'] = pd.to_datetime(all_data['timestamp']).dt.floor(f'{time_interval}T')
    # グループ化したデータをプロトコルごとに集計
    grouped_data = all_data.groupby(['time_bin', 'protocol']).size().unstack(fill_value=0)

    # サービス名をロードしてプロトコル名を正規化
    services = load_services()
    # プロトコル名を正規化
    grouped_data.columns = [normalize_protocol(col, services) for col in grouped_data.columns]

    # データをソートして件数の少ないものから順に積み上げる
    grouped_data = grouped_data.reindex(grouped_data.sum().sort_values().index, axis=1)

    # 色の設定
    colors = plt.cm.tab20.colors

    # 積み上げグラフを作成してPDFに保存
    with PdfPages(pdf_output) as pdf:
        # グラフを作成
        fig, ax = plt.subplots(figsize=(20, 10))
        # 積み上げ棒グラフを作成
        bars = grouped_data.plot(kind='bar', stacked=True, ax=ax, color=colors, edgecolor='black')

        # 縦軸を対数スケールに設定
        ax.set_yscale('log')

        # 件数とプロトコル名をプロット
        for i, container in enumerate(bars.containers):
            # プロトコル名を取得
            protocol_name = grouped_data.columns[i]
            # バーごとに件数を表示
            for bar in container:
                # バーの高さを取得
                height = bar.get_height()#
                # 件数が0より大きい場合
                if height > 0:
                    # ラベルを作成
                    label = f'{protocol_name}:{int(height)}' if not include_legend else f'{int(height)}'
                    # ラベルを表示
                    ax.text(
                        # バーの中央に表示
                        bar.get_x() + bar.get_width() / 2,
                        # バーの高さの中央に表示
                        bar.get_y() + height / 2,
                        # ラベルを表示
                        label,
                        # 中央揃え
                        ha='center',
                        # 中央揃え
                        va='center',
                        # フォントサイズを小さく設定
                        fontsize=6,
                        # フォントカラーを黒に設定
                        color='black'
                    )

        # タイトルを設定
        ax.set_title('Packet Distribution Over Time')
        # X軸のラベルを設定
        ax.set_xlabel('Time')
        # Y軸のラベルを設定
        ax.set_ylabel('Packet Count')
        # X軸のフォーマットを設定
        ax.set_xticks(range(len(grouped_data.index)))
        # X軸のラベルを設定
        ax.set_xticklabels([time_bin.strftime('%m/%d %H:%M') for time_bin in grouped_data.index], rotation=45, ha='right')

        # 凡例を表示する場合
        if include_legend:
            # 凡例を作成
            handles = [mpatches.Patch(facecolor=colors[i % len(colors)], label=label) for i, label in enumerate(grouped_data.columns)]
            # 凡例を表示
            ax.legend(handles=handles, loc='center left', bbox_to_anchor=(1.0, 0.5))
        # 凡例を表示しない場合
        else:
            # 凡例を非表示
            ax.legend().set_visible(False)

        # グラフを保存
        pdf.savefig(fig, bbox_inches='tight')
        # グラフを閉じる
        plt.close(fig)

    # PDFファイルのパスを表示
    print(f"PDF report has been generated: {pdf_output}")

# メイン関数を実行
if __name__ == "__main__":
    # メイン関数を実行
    main()
