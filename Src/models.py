class FunctionSummary:
    def __init__(self, name):
        self.name = name
        self.exec = False
        self.network = False
        self.crypto = False
        self.auth = False
        self.evidence = []

class BinarySummary:
    def __init__(self):
        self.functions = []
        self.strings = []
        self.imports = []
