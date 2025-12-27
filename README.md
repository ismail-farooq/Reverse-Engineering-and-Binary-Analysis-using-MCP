# AI-Assisted Reverse Engineering MCP

This project uses a **Ghidra MCP (Model Context Protocol)** to automatically analyze binaries and flag potential security risks using AI-assisted analysis. It helps reverse engineers identify critical functions, API usage, and potential vulnerabilities.

---

## Features

* **Function Analysis:** Automatically lists functions in a binary and decompiles them.
* **API Flagging:** Detects usage of dangerous APIs, including:

  * Command execution (`system()`, `CreateProcess`)
  * Network activity (`connect`, `send`)
  * Cryptography (`CryptEncrypt`)
  * Authentication functions (`LogonUser`, `AuthenticateUser`)
* **OWASP Top 10 Detection:** Flags functions or strings related to OWASP categories like Injection, Broken Access Control, Cryptographic Failures, SSRF, and more.
* **Binary Metadata:** Extracts strings and imports for further analysis.
* **JSON Output:** Exports analysis results to a structured JSON format for reports or further processing.

---

## Installation

1. Clone the repository:

```bash
git clone https://github.com/yourusername/ai-mcp-reverse-engineering.git
cd ai-mcp-reverse-engineering
```

2. Install required Python packages:

```bash
pip install -r requirements.txt

# to run MCP server
python bridge_mcp_ghidra.py --transport sse --mcp-host 127.0.0.1 --mcp-port 8081 --ghidra-server http://127.0.0.1:8080/
```

3. Ensure Ghidra is installed and `bridge_mcp_ghidra` is configured correctly.

4. Install MCP like Claude, 5ire or Cline, and connect it to `bridge_mcp_ghidra`

## How it Works

1. Decompile functions in the target binary.
2. Scan for known risky APIs and patterns.
3. Check strings and imports for potential security issues.
4. Map findings to OWASP Top 10 categories.
5. Generate a structured JSON report for analysis.

