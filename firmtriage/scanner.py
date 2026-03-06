'''
Purpose:
- load fw file
- call analysis
- aggregate results

store:
self.data
self.results

'''
import os

from firmtriage.strings_scan import strings_scan
from firmtriage.entropy import entropy
from firmtriage.metadata import metadata

class FirmwareScanner:
    def __init__(self, filepath):
        self.filepath = filepath
        self.data = None
        self.results = {}
    
    def load_file(self):
        """Read firmware file into memory"""
        if not os.path.isfile(self.filepath):
            raise FileNotFoundError(f"{self.filepath} not found")
        
        with open(self.filepath, "rb") as f:
            self.data = f.read()
    
    def run_metadata(self):
        """Run metadata analysis"""
        self.results["metadata"] = metadata(self.filepath)
    
    def run_entropy(self):
        """Run entropy analysis"""
        self.results["entropy"] = entropy(self.filepath)
    
    def run_strings(self):
        """Run strings extraction"""
        self.results["strings"] = strings_scan(self.data)
    
    def scan(self):
        """Main orchestration function"""
        
        self.load_file()

        self.run_metadata()
        self.run_entropy()
        self.run_strings()

        return self.results