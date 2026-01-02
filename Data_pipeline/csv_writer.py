import csv  
import os 

class CSVfeatureWriter:
    def __init__(self, filepath, fieldnames):
        self.filepath = filepath
        self.fieldnames = fieldnames
       
        """to automatically create a directory if there isnt one already (resuable code)
        """
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        self._file_exists = os.path.exists(filepath)
        
    def Write(self, feat_dict : dict):
        with open(self.filepath, "a", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=self.fieldnames)
            
            if not self._file_exists:
                writer.writeheader()
                self._file_exists = True
            
            writer.writerow(feat_dict)    
             