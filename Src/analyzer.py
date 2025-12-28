from bridge_mcp_ghidra import *
from models import FunctionSummary, BinarySummary
from pathlib import Path
import json

# Define API patterns to flag functions
API_FLAGS = {
    "exec": ["CreateProcess", "system(", "WinExec", "ShellExecute", "spawn", "popen"],
    "network": ["connect(", "send(", "recv(", "socket(", "WSASocket", "bind(", "listen("],
    "crypto": ["CryptEncrypt", "CryptDecrypt", "CryptAcquireContext", "CryptImportKey"],
    "auth": ["LogonUser", "AuthenticateUser", "CheckPassword", "SSPI"]
}

OWASP_FLAGS = {
    "A01: Broken Access Control": ["LogonUser", "CheckAccess", "SSPI"],
    "A02: Cryptographic Failures": ["CryptEncrypt", "CryptDecrypt", "CryptAcquireContext"],
    "A03: Injection": ["system(", "CreateProcess", "WinExec", "ShellExecute", "popen"],
    "A04: Insecure Design": ["password", "secret", "api_key", "private_key"],  # in strings
    "A05: Security Misconfiguration": ["SetEnvironmentVariable", "WriteFile", "fopen"],
    "A06: Vulnerable Components": ["LoadLibrary", "dlopen"],
    "A07: Authentication Failures": ["AuthenticateUser", "LogonUser"],
    "A08: Software & Data Integrity Failures": ["fwrite", "WriteFile", "patch"],
    "A09: Security Logging & Monitoring Failures": ["fprintf", "WriteFile"],
    "A10: SSRF / Network Issues": ["connect(", "send(", "recv(", "HttpOpenRequest"]
}

def flag_owasp(f_summary: FunctionSummary, code: str, strings: list):
    """
    Check a function for OWASP Top 10 risks based on code and strings
    """
    for category, patterns in OWASP_FLAGS.items():
        for pattern in patterns:
            if pattern in code or any(pattern in s for s in strings):
                if category not in f_summary.evidence:
                    f_summary.evidence.append(f"OWASP: {category} detected via {pattern}")


def flag_function(f_summary: FunctionSummary, code: str):
    """
    Set flags for a function summary based on code and known API patterns
    """
    for flag, patterns in API_FLAGS.items():
        for pattern in patterns:
            if pattern in code:
                setattr(f_summary, flag, True)
                f_summary.evidence.append(f"Detected {flag} API: {pattern}")

# Create the binary summary
binary = BinarySummary()
functions = list_methods()

for fn_name in functions:
    f = FunctionSummary(fn_name)

    try:
        code = decompile_function(fn_name)
    except Exception as e:
        code = ""
        f.evidence.append(f"Failed to decompile: {str(e)}")

    # Flag based on decompiled code
    flag_function(f, code)
    flag_owasp(f, code, binary.strings)

    binary.functions.append(f)

# Capture strings and imports
binary.strings = list_strings()
binary.imports = list_imports()

# Output JSON
def serialize(obj):
    if hasattr(obj, "__dict__"):
        return obj.__dict__
    return str(obj)  # fallback for anything else

output_file = "binary_analysis.json"
with open(output_file, "w") as f:
    json.dump(binary, f, indent=2, default=serialize)

print(f"Analysis saved to {output_file}")