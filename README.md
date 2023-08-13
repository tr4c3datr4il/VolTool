# VolTool
Tools related to Volatility


## VolRecon

Automatic parsing Pstree, Cmdline, Netscan, Filescan to files.

***Compatible with Windows images only***

### Requirements

- Volatility 3 Framework
- Python 3

**Usage**

```
$ chmod +x ./VolRecon.py
$ sudo cp ./VolRecon.py /usr/bin
$ VolRecon.py -h                         
usage: VolRecon.py [-h] -p <PATH> -o <OUTPUT_PATH> [-v] [-csv]

Automatic Parsing Volatility Intels Tool

options:
  -h, --help            show this help message and exit
  -p <PATH>, --path <PATH>
                        Path to the memory image
  -o <OUTPUT_PATH>, --output_path <OUTPUT_PATH>
                        Out files folder
  -v, --verbose         Print plugin's output
  -csv                  Write to csv files

```