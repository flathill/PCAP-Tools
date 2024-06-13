# PCAPファイル解析スクリプト

このリポジトリは、指定されたディレクトリ内のPCAPファイルを解析し、ネットワーク層プロトコルの積み上げグラフを生成するPythonスクリプトを含んでいます。解析結果はPDF形式で出力されます。

## 特徴

- 指定ディレクトリ内の複数のPCAPファイルを解析
- ネットワーク層プロトコルの積み上げグラフを生成
- タイムレンジの間隔を指定可能
- グラフに凡例を表示するオプション
- 解析結果をPDFファイルとして出力

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

### コマンドライン引数

- `--dir`：PCAPファイルを含むディレクトリを指定します。デフォルトは`pcap`ディレクトリです。
- `--legend`：グラフに凡例を表示するオプションです。このオプションを指定すると凡例が表示されます。
- `--interval`：タイムレンジの間隔を分単位で指定します。デフォルトは10分です。

### 実行例

以下は、`normal`ディレクトリ内のPCAPファイルを解析し、タイムレンジの間隔を5分、凡例を表示する設定でスクリプトを実行する例です。

```bash
python pcap_network_analyze.py --dir normal --legend --interval 5
```

### 出力例

実行すると、以下のような出力が得られます：

```bash
Time range interval: 5 minutes
Analysis target directory: normal
Legend: Enabled
Processing file 1/6: 1.pcap: 3617packets [00:04, 870.79packets/s]
Processing file 2/6: 2.pcap: 4737packets [00:04, 1093.12packets/s]
Processing file 3/6: 3.pcap: 3290packets [00:02, 1154.46packets/s]
Processing file 4/6: 4.pcap: 7612packets [00:06, 1206.04packets/s]
Processing file 5/6: 5.pcap: 8798packets [00:08, 985.89packets/s]
Processing file 6/6: 6.pcap: 5789packets [00:04, 1161.23packets/s]
Total packets: 33843
PDF generated: network_layer_packet_analysis_normal_5min-legend.pdf
```

## 注意事項

- PCAPファイルの解析には時間がかかる場合があります。ファイルサイズや数に応じて処理時間が異なりますので、ご注意ください。
- スクリプト実行前に、解析対象のPCAPファイルが指定ディレクトリ内に存在することを確認してください。

## ライセンス

このプロジェクトはMITライセンスのもとで公開されています。詳細はLICENSEファイルをご覧ください。
