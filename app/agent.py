import datetime
import os
import re
import sys
import json
import base64
from typing import Any, AsyncGenerator

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
  
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from google.adk.agents import LlmAgent
from google.adk.apps import App, ResumabilityConfig
from google.adk.tools import AgentTool, ToolContext
from google.adk.workflow import Workflow, Edge, START, node, FunctionNode
from google.adk.events.event import Event
from google.adk.events.request_input import RequestInput
from google.adk.agents.context import Context
from google.adk.tools.mcp_tool import McpToolset
from google.adk.tools.mcp_tool.mcp_session_manager import StdioConnectionParams
from mcp import StdioServerParameters
from google.genai import types

from app.config import config

# ----------------------------------------------------------------------
# Local AES-GCM Cryptography Helpers
# ----------------------------------------------------------------------

def derive_key(password: str, salt_bytes: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt_bytes,
        iterations=100000,
    )
    return kdf.derive(password.encode("utf-8"))

def encrypt_data(password: str, plaintext: str) -> tuple[str, str, str]:
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return (
        base64.b64encode(ciphertext).decode("utf-8"),
        base64.b64encode(salt).decode("utf-8"),
        base64.b64encode(nonce).decode("utf-8")
    )

def decrypt_data(password: str, ciphertext_b64: str, salt_b64: str, nonce_b64: str) -> str:
    ciphertext = base64.b64decode(ciphertext_b64)
    salt = base64.b64decode(salt_b64)
    nonce = base64.b64decode(nonce_b64)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")

# ----------------------------------------------------------------------
# Agent Tools
# ----------------------------------------------------------------------

def encrypt_secret(secret_content: str, tool_context: ToolContext) -> dict:
    """Encrypts a secret string using the session's master password.

    Args:
        secret_content: The plain text content to encrypt.

    Returns:
        dict: containing 'status', 'ciphertext', 'salt', and 'nonce'.
    """
    master_password = tool_context.state.get("master_password")
    if not master_password:
        return {"status": "error", "message": "Master password not set. Tell orchestrator to prompt user."}
    try:
        ciphertext, salt, nonce = encrypt_data(master_password, secret_content)
        return {
            "status": "success",
            "ciphertext": ciphertext,
            "salt": salt,
            "nonce": nonce
        }
    except Exception as e:
        return {"status": "error", "message": f"Encryption failed: {str(e)}"}

def decrypt_secret(ciphertext: str, salt: str, nonce: str, tool_context: ToolContext) -> dict:
    """Decrypts a base64-encoded ciphertext using the session's master password, salt, and nonce.

    Args:
        ciphertext: Base64-encoded encrypted content.
        salt: Base64-encoded salt.
        nonce: Base64-encoded nonce.

    Returns:
        dict: containing 'status' and 'decrypted_content'.
    """
    master_password = tool_context.state.get("master_password")
    if not master_password:
        return {"status": "error", "message": "Master password not set. Tell orchestrator to prompt user."}
    try:
        plaintext = decrypt_data(master_password, ciphertext, salt, nonce)
        return {
            "status": "success",
            "decrypted_content": plaintext
        }
    except Exception as e:
        return {"status": "error", "message": f"Decryption failed: {str(e)}"}

# ----------------------------------------------------------------------
# MCP Server Integration (Phase 3)
# ----------------------------------------------------------------------

current_dir = os.path.dirname(os.path.abspath(__file__))
mcp_server_path = os.path.join(current_dir, "mcp_server.py")

# Configure connection to the local Python MCP server
mcp_toolset = McpToolset(
    connection_params=StdioConnectionParams(
        server_params=StdioServerParameters(
            command=sys.executable,
            args=[mcp_server_path],
        )
    )
)

# ----------------------------------------------------------------------
# Agents Definition (Phase 2)
# ----------------------------------------------------------------------

crypto_agent = LlmAgent(
    name="crypto_agent",
    model=config.model,
    instruction="""You are the Cryptographic Specialist Agent for Ghost.
Your role is to perform encryption and decryption operations for credentials, keys, or secret notes.
You MUST use your local tools `encrypt_secret` and `decrypt_secret` to perform cryptographic operations.
Do not write files or touch the database yourself. Just perform the math and return the ciphertext, salt, and nonce (or plaintext).
""",
    description="Handles secure cryptographic encryption and decryption operations using the master password.",
    tools=[encrypt_secret, decrypt_secret],
)

db_agent = LlmAgent(
    name="db_agent",
    model=config.model,
    instruction="""You are the Database and Ledger Specialist Agent for Ghost.
Your role is to store/retrieve encrypted partitions and manage the tamper-evident audit ledger.
You have access to MCP tools:
- `write_partition`: Saves the ciphertext, salt, and nonce under a partition ID.
- `read_partition`: Retrieves the ciphertext, salt, and nonce for a partition ID.
- `append_ledger_entry`: Appends a cryptographically linked block to the ledger.
- `verify_ledger_integrity`: Validates the ledger's hash chain to detect tampering.
- `reset_ledger`: Clear storage and start a new ledger.

Every time a partition is read or written, you MUST append a ledger entry using `append_ledger_entry`.
The `payload_hash` in the ledger entry should be a SHA-256 hash of the ciphertext. You can compute it or use the ciphertext value.
If you are asked to verify the ledger, call `verify_ledger_integrity` and report the results.
If you are asked to reset the vault, call `reset_ledger`.
""",
    description="Manages database storage of encrypted partitions and updates/verifies the tamper-evident audit ledger.",
    tools=[mcp_toolset],
)

orchestrator_agent = LlmAgent(
    name="orchestrator",
    model=config.model,
    instruction="""You are the Zero-Trust Orchestrator Agent (Ghost).
You coordinate user requests to securely store, retrieve, or audit credentials, keys, and notes.
You do not have direct access to cryptography or databases.

To perform secure storage:
1. Make sure you have the ciphertext, salt, and nonce. If the user provided plain text, call `crypto_agent` to encrypt it first.
2. Once encrypted, call `db_agent` to write the partition and append a ledger entry.
3. Respond to the user confirming the partition ID and that it is encrypted and logged to the ledger.

To perform secure retrieval:
1. Call `db_agent` to read the partition from storage.
2. Call `crypto_agent` to decrypt the ciphertext using the salt and nonce.
3. Present the decrypted credential back to the user.

To verify ledger integrity:
1. Call `db_agent` to verify the ledger's integrity.
2. Report if the chain is intact or if tampering is detected.

To reset the vault:
1. Call `db_agent` to reset the ledger.
If the session lacks the master password, state that it is needed (the orchestrator node will automatically capture it).
""",
    description="Coordinates zero-trust operations between the user, crypto_agent, and db_agent.",
    tools=[AgentTool(crypto_agent), AgentTool(db_agent)],
)

# ----------------------------------------------------------------------
# Workflow Nodes & Logic (Phase 4)
# ----------------------------------------------------------------------

@node(name="security_checkpoint")
def security_checkpoint(ctx: Context, node_input: types.Content) -> Event:
    text = ""
    # Extract text from node_input (START node outputs types.Content)
    if hasattr(node_input, 'parts') and node_input.parts:
        text = "".join([part.text for part in node_input.parts if part.text])
    elif isinstance(node_input, str):
        text = node_input

    # 1. PII Scrubbing (Regexes for SSN, credit cards)
    ssn_pattern = r'\b\d{3}-\d{2}-\d{4}\b'
    card_pattern = r'\b(?:\d[ -]*?){13,16}\b'
    scrubbed_text = re.sub(ssn_pattern, '[REDACTED_SSN]', text)
    scrubbed_text = re.sub(card_pattern, '[REDACTED_CARD]', scrubbed_text)

    # 2. Prompt Injection Detection
    injection_keywords = [
        "ignore previous instructions",
        "ignore system prompt",
        "bypass security",
        "override system instructions",
        "you must now act as",
        "system prompt override",
        "do not follow safety"
    ]
    detected_injection = False
    for kw in injection_keywords:
        if kw in scrubbed_text.lower():
            detected_injection = True
            break

    # Structured Audit Log
    log_severity = "INFO"
    log_message = "Input security check passed."
    if detected_injection:
        log_severity = "CRITICAL"
        log_message = f"Prompt injection detected in input: '{text}'"
    elif scrubbed_text != text:
        log_severity = "WARNING"
        log_message = "PII data scrubbed from input."

    # Domain specific rule: Log a warning if resetting database
    if "reset" in scrubbed_text.lower() or "delete" in scrubbed_text.lower():
        log_severity = "WARNING"
        log_message = f"High-risk operation requested: {scrubbed_text}"

    audit_log = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "severity": log_severity,
        "message": log_message,
        "session_id": ctx.session.id
    }
    
    if "audit_logs" not in ctx.state:
        ctx.state["audit_logs"] = []
    ctx.state["audit_logs"].append(audit_log)
    
    # Also write to local log file
    db_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "ghost_db"))
    os.makedirs(db_dir, exist_ok=True)
    with open(os.path.join(db_dir, "security_audit.log"), "a") as f:
        f.write(json.dumps(audit_log) + "\n")

    if detected_injection:
        return Event(
            route="violation",
            output="Security check failed: Prompt injection attempt detected.",
            state={"violation_reason": "injection"}
        )

    # Create new Content object with scrubbed text for downstream node
    scrubbed_content = types.Content(role='user', parts=[types.Part.from_text(text=scrubbed_text)])
    
    return Event(
        route="clean",
        output=scrubbed_content,
        state={"user_input_scrubbed": scrubbed_text}
    )

@node(name="security_violation")
def security_violation(ctx: Context, node_input: str) -> Event:
    msg = "🚨 [Ghost Security Violation] Your request has been blocked by the Zero-Trust Security Sentinel."
    if ctx.state.get("violation_reason") == "injection":
        msg += "\nReason: Prompt injection attempt detected."
    
    # We yield Event(content=...) for UI display
    yield Event(content=types.Content(role='model', parts=[types.Part.from_text(text=msg)]))
    yield Event(output=msg)

@node(name="orchestrator_node", rerun_on_resume=True)
async def orchestrator_node(ctx: Context, node_input: types.Content) -> Event:
    # Check if we have the master password in the session state
    if "master_password" not in ctx.state:
        # Check if it was provided in resume_inputs
        if ctx.resume_inputs and "master_password" in ctx.resume_inputs:
            ctx.state["master_password"] = ctx.resume_inputs["master_password"]
        else:
            # Yield RequestInput to pause the workflow and ask for it
            yield RequestInput(
                interrupt_id="master_password",
                message="🔒 [Ghost Cryptographic Vault] Please enter your master password to authorize cryptographic operations:"
            )
            return

    # Run the orchestrator agent and stream its events
    orchestrator_output = ""
    async for event in orchestrator_agent.run_async(ctx):
        yield event
        if event.output is not None:
            orchestrator_output = event.output

    # Yield the final output event
    yield Event(output=orchestrator_output)

# ----------------------------------------------------------------------
# Graph / Application definition
# ----------------------------------------------------------------------

edges = [
    Edge(from_node=START, to_node=security_checkpoint),
    Edge(from_node=security_checkpoint, to_node=security_violation, route='violation'),
    Edge(from_node=security_checkpoint, to_node=orchestrator_node, route='clean'),
]

root_agent = Workflow(
    name="ghost_workflow",
    edges=edges,
    description="Ghost: Zero-Trust Cryptographic Concierge Agent workflow.",
)

app = App(
    name="app",  # MUST match the agent directory name 'app' to avoid session mismatch
    root_agent=root_agent,
    resumability_config=ResumabilityConfig(is_resumable=True),
)
