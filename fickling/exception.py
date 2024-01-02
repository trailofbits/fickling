class UnsafeFileError(Exception):
    def __init__(self, filepath, info):
        super().__init__()
        self.filepath = filepath
        self.info = info

    def __str__(self):
        return f"Safety results for {self.filepath} : {str(self.info)}"
    
class WrongMethodError(Exception):
    def __init__(self):
        super().__init__()

    def __str__(self):
        return f"This method has been removed. Use fickling.is_likely_safe() on the pickle file or analysis.check_safety() on the Pickled object"
