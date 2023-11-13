#!/usr/bin/env python3
from volatility3.framework.interfaces.configuration import path_join
from volatility3.framework.plugins import construct_plugin
from volatility3.framework import contexts, automagic, interfaces
from volatility3.cli import text_renderer
from volatility3 import plugins
import volatility3.framework
import argparse, logging
import os, sys, io, tempfile

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

volatility3.framework.require_interface_version(2, 0, 0)

# Redirect stdout to both log files and terminal
class RedirectOutput(object):
    def __init__(self, output_file, verbose):
        # Handling 'verbose' flag
        if verbose:
            self.terminal = sys.stdout
            self.log = open(output_file, "w")
        else:
            self.terminal = open(os.devnull, "w")
            self.log = open(output_file, "w")
            
    def write(self, message):
        self.terminal.write(message)
        self.log.write(message)  

    def flush(self):
        # this flush method is needed for python 3 compatibility.
        # this handles the flush command by doing nothing.
        # you might want to specify some extra behavior here.
        pass  

def fileHandler(output_dir):
    class CLIFileHandler(interfaces.plugins.FileHandlerInterface):
        """The FileHandler from Volatility3 CLI"""
        def _get_final_filename(self):
            """Gets the final filename"""
            if output_dir is None:
                raise TypeError("Output directory is not a string")
            os.makedirs(output_dir, exist_ok = True)

            pref_name_array = self.preferred_filename.split('.')
            filename, extension = os.path.join(output_dir, '.'.join(pref_name_array[:-1])), pref_name_array[-1]
            output_filename = f"{filename}.{extension}"

            counter = 1
            if os.path.exists(output_filename):
                os.remove(output_filename)
            return output_filename

    class CLIDirectFileHandler(CLIFileHandler):
        """We want to save our files directly to disk"""
        def __init__(self, filename: str):
            fd, self._name = tempfile.mkstemp(suffix = '.vol3', prefix = 'tmp_', dir = output_dir)
            self._file = io.open(fd, mode = 'w+b')
            CLIFileHandler.__init__(self, filename)
            for item in dir(self._file):
                if not item.startswith('_') and not item in ['closed', 'close', 'mode', 'name']:
                    setattr(self, item, getattr(self._file, item))

        def __getattr__(self, item):
            return getattr(self._file, item)

        @property
        def closed(self):
            return self._file.closed

        @property
        def mode(self):
            return self._file.mode

        @property
        def name(self):
            return self._file.name

        def close(self):
            """Closes and commits the file (by moving the temporary file to the correct name"""
            # Don't overcommit
            if self._file.closed:
                return

            self._file.close()
            output_filename = self._get_final_filename()
            os.rename(self._name, output_filename)

    return CLIDirectFileHandler

class DumpHandler:
    def __init__(self, image_path, output_path, verbose, csv):
        self.ctx = contexts.Context()
        self.failures = volatility3.framework.import_files(volatility3.plugins, True)  # Load plugins
        if self.failures:
            logger.warning(f"Volatility can't load these plugins: {self.failures}")
        else:
            logger.info("Plugins are loaded without failures")

        self.plugin_list = volatility3.framework.list_plugins()
        self.base_config_path = "plugins"
        self.plugin_name = ["windows.dumpfiles.DumpFiles",
                            "windows.memmap.Memmap",
                            "windows.pslist.PsList"]

        self.output_path = output_path
        self.image_path = self.handlePath(image_path, self.output_path)
        self.verbose = verbose
        self.csv = csv
        
    # Convert normal path to URL path
    def handlePath(self, image_path, output_path):
        if not (os.path.exists(output_path)):
            os.makedirs(output_path)
        
        if image_path.startswith("./") or image_path.startswith("../") or image_path.startswith(""):
            abs_path = os.path.abspath(image_path)
            file_url = "file://" + abs_path
            return file_url
        elif image_path.startswith("file://"):
            return image_path
        else:
            return image_path
    
    # Building context to run
    def buildContext(self, plugin):
        _config_path = path_join(self.base_config_path, plugin.__name__)
        available_automagics = automagic.available(self.ctx)
        plugin_config_path = interfaces.configuration.path_join(self.base_config_path, plugin.__name__)
        automagics = automagic.choose_automagic(available_automagics, plugin)
        self.ctx.config["automagic.LayerStacker.stackers"] = automagic.stacker.choose_os_stackers(plugin)
        self.ctx.config["automagic.LayerStacker.single_location"] = self.image_path
        constructed = construct_plugin(self.ctx, automagics, plugin, self.base_config_path, None, fileHandler(self.output_path))

        return constructed

    # Parse output to files (log/csv)
    def prettyPrint(self, constructed, output_file, verbose):
        sys.stdout = RedirectOutput(output_file, verbose)
        result = text_renderer.PrettyTextRenderer().render(constructed.run())
        sys.stdout.log.close()
        sys.stdout = sys.__stdout__

    def prettyCSV(self, constructed, output_file, verbose):
        sys.stdout = RedirectOutput(output_file, verbose)
        result = text_renderer.CSVRenderer().render(constructed.run())
        sys.stdout.log.close()
        sys.stdout = sys.__stdout__
        
class ProcDump(DumpHandler):
    def __init__(self, image_path, output_path, verbose, csv, pid_list):
        super().__init__(image_path, output_path, verbose, csv)
        self.pid_list = pid_list
        self.plugin = self.plugin_list[self.plugin_name[2]]
        self.handlePID()

    def handlePID(self):
        ctx_pid = [int(pid) for pid in self.pid_list]
        self.ctx.config["plugins.PsList.pid"] = ctx_pid
        self.ctx.config["plugins.PsList.dump"] = True
        constructed = super().buildContext(self.plugin)

        if not constructed:
            logger.info("Plugin could not extract anything")
        if self.csv:
            output_file = self.output_path + '/' + self.plugin_name[2].split(".")[1] + ".csv"
            super().prettyCSV(constructed, output_file, self.verbose)    
        else:
            output_file = self.output_path + '/' + self.plugin_name[2].split(".")[1] + ".log"
            super().prettyPrint(constructed, output_file, self.verbose)
        
class FileDump(DumpHandler):
    def __init__(self, image_path, output_path, verbose, csv, offset_list):
        super().__init__(image_path, output_path, verbose, csv)
        self.offset_list = offset_list
        self.plugin = self.plugin_list[self.plugin_name[0]]
        print(self.plugin_name)
        self.handleOffset()

    def handleOffset(self):
        for ctx_offset in self.offset_list:
            self.ctx.config["plugins.DumpFiles.virtaddr"] = int(ctx_offset, 16)
            constructed = super().buildContext(self.plugin)

            if not constructed:
                logger.info("Plugin could not extract anything")
            if self.csv:
                output_file = self.output_path + '/' + self.plugin_name[0].split(".")[1] + ".csv"
                super().prettyCSV(constructed, output_file, self.verbose)    
            else:
                output_file = self.output_path + '/' + self.plugin_name[0].split(".")[1] + ".log"
                super().prettyPrint(constructed, output_file, self.verbose)
        
class MemmapDump(DumpHandler):
    def __init__(self, image_path, output_path, verbose, csv, pid_list):
        super().__init__(image_path, output_path, verbose, csv)
        self.pid_list = pid_list
        self.plugin = self.plugin_list[self.plugin_name[1]]
        self.handlePID()

    def handlePID(self):
        for ctx_pid in self.pid_list:
            self.ctx.config["plugins.Memmap.pid"] = int(ctx_pid)
            self.ctx.config["plugins.Memmap.dump"] = True
            constructed = super().buildContext(self.plugin)

            if not constructed:
                logger.info("Plugin could not extract anything")
            if self.csv:
                output_file = self.output_path + '/' + self.plugin_name[1].split(".")[1] + ".csv"
                super().prettyCSV(constructed, output_file, self.verbose)    
            else:
                output_file = self.output_path + '/' + self.plugin_name[1].split(".")[1] + ".log"
                super().prettyPrint(constructed, output_file, self.verbose)       
  
        
def parseListOrFile(value):
    if ',' in value:
        return value.split(',')
    else:
        with open(value, 'r') as file:
            return file.read().splitlines()

def main():
    parser = argparse.ArgumentParser(description="Automatic Dumping Volatility Tool")
    parser.add_argument("-p", "--path", metavar="<PATH>", help="Path to the memory image", required=True)
    parser.add_argument("-o", "--output_path", metavar="<OUTPUT_PATH>", help="Out files folder", required=True)
    parser.add_argument("-v", "--verbose", action="store_true", help="Print plugin's output")
    parser.add_argument("-csv", action="store_true", help="Write to csv files")
    
    subparsers = parser.add_subparsers(help='Dump Modes')
    
    group_filedump = subparsers.add_parser("filedump")
    group_filedump.set_defaults(group="filedump")  
    group = group_filedump.add_mutually_exclusive_group(required=True)
    group.add_argument("-pid", metavar="<PROCESS' ID>", type=parseListOrFile, help="Process' ID list")
    group.add_argument("-off", "--offset", metavar="<FILE'S OFFSET>", type=parseListOrFile, help="File's offset list")

    group_procdump = subparsers.add_parser("procdump")
    group_procdump.set_defaults(group="procdump")
    group_procdump.add_argument("-pid", metavar="<PROCESS' ID>", type=parseListOrFile, help="Process' ID list", required=True)

    group_memmap = subparsers.add_parser("memmap")
    group_memmap.set_defaults(group="memmap")
    group_memmap.add_argument("-pid", metavar="<PROCESS' ID>", type=parseListOrFile, help="Process' ID list", required=True)

    args = parser.parse_args()

    image_path = args.path
    output_path = args.output_path
    verbose = args.verbose
    csv = args.csv
    
    if args.group == 'procdump':
        pid = args.pid
        ProcDump(image_path, output_path, verbose, csv, pid)
    elif args.group == 'memmap':
        pid = args.pid
        MemmapDump(image_path, output_path, verbose, csv, pid)
    else:
        pid = args.pid
        offset = args.offset
        FileDump(image_path, output_path, verbose, csv, offset)

if __name__=='__main__':
    main()