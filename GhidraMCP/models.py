# models.py

class FunctionSummary:
    def __init__(self, name):
        self.name = name
        self.exec = False
        self.network = False
        self.crypto = False
        self.auth = False
        self.evidence = []

    def to_dict(self):
        return {
            "name": self.name,
            "exec": self.exec,
            "network": self.network,
            "crypto": self.crypto,
            "auth": self.auth,
            "evidence": self.evidence
        }


class BinarySummary:
    def __init__(self):
        self.functions = []
        self.strings = []
        self.imports = []

    def to_dict(self):
        return {
            "functions": [f.to_dict() for f in self.functions],
            "strings": self.strings,
            "imports": self.imports
        }
