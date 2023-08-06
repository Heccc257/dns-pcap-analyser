# dns-pcap-analyser

## 使用方法
`bin/dns_pcap_analyser_app [-f <file or dir>] [-o <output_dir>]`
* 必须指定原始数据的路径
    * 如果是dir则会找到目录下所有`.dat`后缀的文件
* 可以指定 output 的路径，默认为 `test/output.txt`