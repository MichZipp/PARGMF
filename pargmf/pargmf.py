import logging
import os, sys
import zipfile
import shutil
import traceback

from utils import process_sysmon

# Make sure we can import cuckoo packages
try:
    from lib.cuckoo.common.abstracts import Processing
    from lib.cuckoo.common.exceptions import CuckooProcessingError
    from lib.cuckoo.common.objects import File
except Exception as e:
    print(f'Cannot import cuckoo modules: {e}')
    
log = logging.getLogger(__name__)

__author__ = "Michael Zipperle"
__version__ = "0.0.1"


class PARGMF(Processing):
    """
    CAPEv2 PARGMF Processing Module
    """
    def run(self):
        try:
            self.key = "graph"
            data = None
            
            log_path = os.path.join(self.analysis_path, 'evtx')
            evtx_path = os.path.join(log_path , "evtx.zip") 
            tmp_path = os.path.join(log_path, "tmp")  
            output_path = os.path.join(self.analysis_path, 'graph')
            log.info(f'Task {self.task}')
            package = self.task["package"]            
            filename = File(self.task["target"]).get_name().lower()
            custom = self.task["custom"] 
                        
            if not os.path.exists(output_path):
                os.mkdir(output_path)
            else:
                shutil.rmtree(output_path)
            
                os.mkdir(output_path)
            
            try:
                with zipfile.ZipFile(evtx_path) as z:
                    z.extractall(tmp_path)  
            except Exception as e: 
                raise CuckooProcessingError(f"{evtx_path} doesn't exist")

            tmp_sysmon_evtx_path = os.path.join(tmp_path, "Microsoft-Windows-Sysmon%4Operational.evtx")           
            sysmon_evtx_path = os.path.join(log_path, "sysmon.evtx")

            try:
                shutil.copyfile(tmp_sysmon_evtx_path, sysmon_evtx_path)
            except FileNotFoundError:
                raise CuckooProcessingError(f"{tmp_sysmon_evtx_path} doesn't exist")
            
            # Clean up tmp folder 
            try:
                shutil.rmtree(tmp_path)
            except Exception as e:
                print(e)

            process_sysmon(sysmon_evtx_path, output_path, filename, package, custom)  

        except Exception as e:
            traceback.print_exc()
            raise CuckooProcessingError("Graph failed")

        return data
