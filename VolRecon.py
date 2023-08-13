#!/usr/bin/env python3
from volatility3.framework.interfaces.configuration import path_join
from volatility3.framework.plugins import construct_plugin
from volatility3.framework import contexts, automagic
from volatility3.cli import text_renderer
from volatility3 import plugins
import volatility3.framework
import argparse, logging
import os, sys

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Checking Volatility's version
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

# Main function
class VolRecon:
    def __init__(self, image_path, output_path, verbose, csv):
        ctx = contexts.Context()
        failures = volatility3.framework.import_files(plugins, True) # Load plugins
        if failures:
            logger.warning(f"Volatility can't load these plugins: {failures}")
        else:
            logger.info("Plugins are loaded without failures")
        plugin_list = volatility3.framework.list_plugins()
        base_config_path = "plugins"
        plugin_names = ["windows.pstree.PsTree", "windows.cmdline.CmdLine", 
                       "windows.netscan.NetScan", "windows.filescan.FileScan"]
        image_path = self.handlePath(image_path)
        for p in plugin_names:
            print(f"{p.split('.')[1].upper()} starting...")
            plugin = plugin_list[p]
            constructed = self.buildContext(image_path, ctx, base_config_path, plugin) # Run plugins
            if not constructed:
                logger.info("Plugin could not extract anything")
            if csv:
                output_file = output_path + p.split(".")[1] + ".csv"
                self.prettyCSV(constructed, output_file, verbose)    
            else:
                output_file = output_path + p.split(".")[1] + ".log"
                self.prettyPrint(constructed, output_file, verbose)
    
    # Convert normal path to URL path
    def handlePath(self, image_path):
        if image_path.startswith("./") or image_path.startswith("../") or image_path.startswith(""):
            abs_path = os.path.abspath(image_path)
            file_url = "file://" + abs_path
            return file_url
        elif image_path.startswith("file://"):
            return image_path
        else:
            return image_path
    
    # Building context to run
    def buildContext(self, image_path, ctx, base_config_path, plugin):
        _config_path = path_join(base_config_path, plugin.__name__)
        available_automagics = automagic.available(ctx)
        automagics = automagic.choose_automagic(available_automagics, plugin)
        ctx.config["automagic.LayerStacker.stackers"] = automagic.stacker.choose_os_stackers(plugin)
        ctx.config["automagic.LayerStacker.single_location"] = image_path
        constructed = construct_plugin(ctx, automagics, plugin, base_config_path, None, None)
           
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
        

def main():
    parser = argparse.ArgumentParser(description="Automatic Parsing Volatility Intels Tool")
    parser.add_argument("-p", "--path", metavar="<PATH>", help="Path to the memory image", required=True)
    parser.add_argument("-o", "--output_path", metavar="<OUTPUT_PATH>", help="Out files folder", required=True)
    parser.add_argument("-v", "--verbose", action="store_true", help="Print plugin's output")
    parser.add_argument("-csv", action="store_true", help="Write to csv files")
    args = parser.parse_args()
    image_path = args.path
    output_path = args.output_path
    verbose = True if args.verbose else False
    csv = True if args.csv else False
    
    VolRecon(image_path, output_path, verbose, csv)

if __name__=="__main__":
    main()