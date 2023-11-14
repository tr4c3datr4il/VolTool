#!/usr/bin/env python3
from volatility3.framework.interfaces.configuration import path_join
from volatility3.framework.plugins import construct_plugin
from volatility3.framework import contexts, automagic, interfaces
from volatility3.cli import text_renderer
import volatility3.framework
import argparse, logging
import os, sys, io
import graphviz

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

volatility3.framework.require_interface_version(2, 0, 0)

    
class PsScan:
    def __init__(self, image_path, output_path):
        ctx = contexts.Context()
        failures = volatility3.framework.import_files(volatility3.plugins, True)  # Load plugins
        if failures:
            logger.warning(f"Volatility can't load these plugins: {failures}")
        else:
            logger.info("Plugins are loaded without failures")

        plugin_list = volatility3.framework.list_plugins()
        base_config_path = "plugins"
        plugin_name = "windows.psscan.PsScan"
        plugin = plugin_list[plugin_name]


        output_path = output_path
        image_path = self.handlePath(image_path, output_path)
        
        
        constructed = self.buildContext(ctx, base_config_path, image_path, plugin)
        pslist = self.getPsList(constructed, output_path)
        self.drawGraph(output_path, pslist)
        
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
    def buildContext(self, ctx, base_config_path, image_path, plugin):
        _config_path = path_join(base_config_path, plugin.__name__)
        available_automagics = automagic.available(ctx)
        plugin_config_path = interfaces.configuration.path_join(base_config_path, plugin.__name__)
        automagics = automagic.choose_automagic(available_automagics, plugin)
        ctx.config["automagic.LayerStacker.stackers"] = automagic.stacker.choose_os_stackers(plugin)
        ctx.config["automagic.LayerStacker.single_location"] = image_path
        constructed = construct_plugin(ctx, automagics, plugin, base_config_path, None, None)

        return constructed

    def getPsList(self, constructed):
        io_stdout = io.StringIO()
        sys.stdout = io_stdout
        result = text_renderer.PrettyTextRenderer().render(constructed.run())
        pslist = io_stdout.getvalue()
        sys.stdout = sys.__stdout__

        return pslist.splitlines()

    def drawGraph(self, output_path, pslist):
        HEADER = pslist[0]
        proc_list = pslist[1:]
        LABEL_FORMAT = "{} | {} | {}"
        
        dot = graphviz.Digraph(comment="Process Tree",graph_attr={"ranksep":"2","nodesep":"1.5"})
        edges = []
        
        for process in proc_list:
            process = process.split('|')
            pid = process[1].strip()
            ppid = process[2].strip()
            proc_name = process[3].strip()
            exit_time = process[10].strip()
            state = None
            
            edge = (ppid, pid)
            edges.append(edge)
            
            if exit_time == 'N/A':
                state = 'running' 
                dot.node(pid,
                         label=LABEL_FORMAT.format(pid, proc_name, state),
                         shape='record')
            else:
                state = 'exited\\n' + exit_time
                dot.node(pid,
                         label=LABEL_FORMAT.format(pid, proc_name, state),
                         shape='record',
                         style = 'filled', 
                         fillcolor = 'lightgray')
            
        dot.edges(edges)
        dot.render(f'{output_path}/testing_hihi',format='png', cleanup=True)
    
def main():
    parser = argparse.ArgumentParser(description="Draw Process Tree Tool")
    
    parser.add_argument("-p", "--path", metavar="<PATH>", help="Path to the memory image", required=True)
    parser.add_argument("-o", "--output_path", metavar="<OUTPUT_PATH>", help="Out files folder", required=True)
    
    args = parser.parse_args()
    
    image_path = args.path
    output_path = args.output_path
    
    PsScan(image_path, output_path)
    
if __name__=='__main__':
    main()