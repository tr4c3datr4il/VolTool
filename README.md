# VolTool
Tools related to Volatility

***Compatible with Windows images only***

[Reference - ForensicxLab](https://forensicxlab.github.io/)

### Requirements

- Volatility 3 Framework
- Python 3

## VolRecon

Automatic parsing Pstree, Cmdline, Netscan, Filescan to files.

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

## VolAutoDump

Automatic dumping given PID list or offset list, using PsList, Memmap and DumpFiles to dump.

**Usage**

```
$ chmod +x ./VolAutoDump.py
$ sudo cp ./VolAutoDump.py /usr/bin
$ VolAutoDump.py -h
usage: VolAutoDump.py [-h] -p <PATH> -o <OUTPUT_PATH> [-v] [-csv] {filedump,procdump,memmap} ...

Automatic Dumping Volatility Tool

positional arguments:
  {filedump,procdump,memmap}
                        Dump Modes

options:
  -h, --help            show this help message and exit
  -p <PATH>, --path <PATH>
                        Path to the memory image
  -o <OUTPUT_PATH>, --output_path <OUTPUT_PATH>
                        Out files folder
  -v, --verbose         Print plugin's output
  -csv                  Write to csv files
```



### TO-DO List:
- Optimize code
- Update stdout handler
- Update dumping modes in VolAutoDump
- Tried to change PrettyPrint's output
- something fun ...