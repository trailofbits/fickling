class UnsafeFileError(Exception):
    def __init__(self, filepath, info):
        super().__init__()
        self.filepath = filepath
        self.info = info

    def __str__(self):
        return f"Safety results for {self.filepath} : {str(self.info)}"
