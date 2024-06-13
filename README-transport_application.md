# PCAPファイル解析スクリプト

このPythonスクリプトは、指定されたディレクトリ内のPCAPファイルを解析し、トランスポート層およびアプリケーション層のプロトコルごとにデータをグループ化し、積み上げ棒グラフとしてPDFレポートを生成します。

## 特徴

- `pyshark`を使用してPCAPファイルを解析します。
- トランスポート層およびアプリケーション層のプロトコルごとにデータをグループ化します。
- ユーザー定義の時間間隔（デフォルトは10分）でデータを集計します。
- 積み上げ棒グラフとしてPDFレポートを生成します。
- PDFレポートに凡例をオプションで含めることができます。
- 各PCAPファイルの処理進行状況を表示します。

## 必要条件

- Python 3.x
- 必要なPythonパッケージ：
  - `argparse`
  - `pandas`
  - `matplotlib`
  - `pyshark`
  - `tqdm`

## インストール

1. リポジトリをクローンします：

```bash
git clone https://github.com/flathill/PCAP-Tools.git
cd PCAP-Tools
```

2. 必要なPythonパッケージをインストールします：

```bash
pip install pyshark pandas matplotlib tqdm argparse
```

## 使用方法

以下のコマンドでスクリプトを実行します：

```bash
python3 pcap_network_analyze.py [--dir DIR] [--legend] [--interval INTERVAL]
```

### オプション

- `--dir DIR`：PCAPファイルが含まれるディレクトリ（デフォルトは`pcap`）。
- `--legend`：出力PDFに凡例を含める。
- `--interval INTERVAL`：時間間隔を分単位で指定（デフォルトは10分）。

### 実行例

1. `normal`ディレクトリ内のPCAPファイルを5分間隔で解析し、PDFレポートに凡例を含める：

```bash
python3 pcap_network_analyze.py --dir normal --legend --interval 5
```

2. デフォルトディレクトリ（`pcap`）内のPCAPファイルを10分間隔で解析し、凡例を含めない：

```bash
python3 pcap_network_analyze.py
```

3. 実行のサンプル（デフォルトディレクトリ、10分間隔、凡例あり）：

```bash
$ python3 pcap_network_analyze.py --interval 10 --legend
Time range interval: 10 minutes
Analysis target directory: pcap
Legend: Enabled
Processing file 1/6: 1.pcap: 3617 packets [00:04, 894.34 packets/s]
Processing file 2/6: 2.pcap: 4737 packets [00:05, 855.18 packets/s]
Processing file 3/6: 3.pcap: 3290 packets [00:03, 876.68 packets/s]
Processing file 4/6: 4.pcap: 7612 packets [00:08, 942.08 packets/s]
Processing file 5/6: 5.pcap: 8798 packets [00:11, 747.91 packets/s]
Processing file 6/6: 6.pcap: 5789 packets [00:06, 851.84 packets/s]
Total packets: 33843
PDF generated: transport_application_protocol_analyze_pcap-10min-legend.pdf
```

### 出力

スクリプトは、指定されたディレクトリ名と時間間隔を含む名前のPDFレポートを生成します。例えば：

- `transport_application_protocol_analyze_normal-5min-legend.pdf`
- `transport_application_protocol_analyze_pcap-10min.pdf`

## スクリプト詳細

このスクリプトは以下の手順を実行します：

1. コマンドライン引数を解析します。
2. `/etc/services`からプロトコル情報をロードします。
3. 指定されたディレクトリ内の各PCAPファイルを読み込み解析します。
4. トランスポート層およびアプリケーション層のプロトコルと時間間隔ごとにデータをグループ化します。
5. 積み上げ棒グラフを生成し、PDFレポートとして保存します。

## ライセンス

このプロジェクトはMITライセンスの下でライセンスされています。詳細については[LICENSE](LICENSE)ファイルを参照してください。

## 貢献

1. リポジトリをフォークします。
2. フィーチャーブランチを作成します（`git checkout -b feature/your-feature`）。
3. 変更をコミットします（`git commit -am 'Add some feature'`）。
4. ブランチにプッシュします（`git push origin feature/your-feature`）。
5. プルリクエストを作成します。

## 謝辞

- [pyshark](https://github.com/KimiNewt/pyshark)
- [pandas](https://pandas.pydata.org/)
- [matplotlib](https://matplotlib.org/)
- [tqdm](https://github.com/tqdm/tqdm)
