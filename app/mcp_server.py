import os
import json
import datetime
import hashlib
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("ghost-vault")

# Configure database directory under the project folder (outside the app code directory)
DB_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "ghost_db"))
PARTITIONS_DIR = os.path.join(DB_DIR, "partitions")
LEDGER_PATH = os.path.join(DB_DIR, "ledger.json")

def ensure_db_dirs():
    os.makedirs(DB_DIR, exist_ok=True)
    os.makedirs(PARTITIONS_DIR, exist_ok=True)

@mcp.tool()
def write_partition(partition_id: str, ciphertext: str, salt: str, nonce: str) -> str:
    """Writes an encrypted data partition to the secure database storage.

    Args:
        partition_id: A unique identifier for the partition.
        ciphertext: The encrypted content (hex-encoded or base64-encoded).
        salt: The key derivation salt (hex-encoded).
        nonce: The encryption nonce (hex-encoded).

    Returns:
        A confirmation message.
    """
    ensure_db_dirs()
    file_path = os.path.join(PARTITIONS_DIR, f"{partition_id}.json")
    
    data = {
        "ciphertext": ciphertext,
        "salt": salt,
        "nonce": nonce
    }
    
    with open(file_path, "w") as f:
        json.dump(data, f, indent=2)
        
    return f"Success: Partition '{partition_id}' written to secure storage."

@mcp.tool()
def read_partition(partition_id: str) -> str:
    """Reads an encrypted data partition from the secure database storage.

    Args:
        partition_id: The unique identifier of the partition.

    Returns:
        A JSON string containing ciphertext, salt, and nonce, or an error message.
    """
    ensure_db_dirs()
    file_path = os.path.join(PARTITIONS_DIR, f"{partition_id}.json")
    
    if not os.path.exists(file_path):
        return f"Error: Partition '{partition_id}' not found."
        
    with open(file_path, "r") as f:
        data = json.load(f)
        
    return json.dumps(data)

@mcp.tool()
def append_ledger_entry(operation: str, partition_id: str, payload_hash: str) -> str:
    """Appends an entry to the tamper-evident audit ledger hash chain.

    Args:
        operation: The database operation performed (e.g., STORE, RETRIEVE, VERIFY).
        partition_id: The unique partition identifier.
        payload_hash: A SHA-256 hash of the payload for integrity checks.

    Returns:
        A success message with the block index and hash.
    """
    ensure_db_dirs()
    
    # Load existing ledger
    ledger = []
    if os.path.exists(LEDGER_PATH):
        try:
            with open(LEDGER_PATH, "r") as f:
                ledger = json.load(f)
        except json.JSONDecodeError:
            ledger = []

    # Compute prev_hash
    prev_hash = "0"
    if ledger:
        prev_hash = ledger[-1]["hash"]

    index = len(ledger)
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    
    # Hash chain linking: hash = sha256(index + timestamp + operation + partition_id + payload_hash + prev_hash)
    content_to_hash = f"{index}{timestamp}{operation}{partition_id}{payload_hash}{prev_hash}"
    block_hash = hashlib.sha256(content_to_hash.encode("utf-8")).hexdigest()
    
    block = {
        "index": index,
        "timestamp": timestamp,
        "operation": operation,
        "partition_id": partition_id,
        "payload_hash": payload_hash,
        "prev_hash": prev_hash,
        "hash": block_hash
    }
    
    ledger.append(block)
    
    with open(LEDGER_PATH, "w") as f:
        json.dump(ledger, f, indent=2)
        
    return f"Success: Audit ledger block #{index} appended. Hash: {block_hash[:10]}..."

@mcp.tool()
def verify_ledger_integrity() -> str:
    """Validates the entire audit ledger hash chain to detect any tampering or edits.

    Returns:
        A report summarizing the validation status of the ledger.
    """
    ensure_db_dirs()
    
    if not os.path.exists(LEDGER_PATH):
        return "Validation Error: Audit ledger file does not exist."
        
    try:
        with open(LEDGER_PATH, "r") as f:
            ledger = json.load(f)
    except json.JSONDecodeError:
        return "CRITICAL: Audit ledger is corrupt or invalid JSON."

    if not ledger:
        return "Ledger is empty."

    # Validate each block
    for i, block in enumerate(ledger):
        # 1. Verify prev_hash link
        if i == 0:
            if block["prev_hash"] != "0":
                return "CRITICAL: Genesis block prev_hash is not '0'."
        else:
            prev_block = ledger[i-1]
            if block["prev_hash"] != prev_block["hash"]:
                return f"CRITICAL: Ledger chain broken at block #{i}! Expected prev_hash '{prev_block['hash'][:10]}...', but found '{block['prev_hash'][:10]}...'."

        # 2. Recalculate block hash
        content_to_hash = f"{block['index']}{block['timestamp']}{block['operation']}{block['partition_id']}{block['payload_hash']}{block['prev_hash']}"
        expected_hash = hashlib.sha256(content_to_hash.encode("utf-8")).hexdigest()
        
        if block["hash"] != expected_hash:
            return f"CRITICAL: Hash mismatch at block #{i}! Block has been tampered with. Stored: '{block['hash'][:10]}...', Calculated: '{expected_hash[:10]}...'."

    return f"Success: Audit ledger is fully intact and verified. Total blocks validated: {len(ledger)}."

@mcp.tool()
def reset_ledger() -> str:
    """Resets the partition files and clear/re-initialize the audit ledger.

    Returns:
        A confirmation message.
    """
    ensure_db_dirs()
    
    # Clean partitions directory
    if os.path.exists(PARTITIONS_DIR):
        for f in os.listdir(PARTITIONS_DIR):
            file_path = os.path.join(PARTITIONS_DIR, f)
            if os.path.isfile(file_path):
                os.remove(file_path)

    # Initialize ledger with genesis block
    ledger = []
    index = 0
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    prev_hash = "0"
    operation = "GENESIS"
    partition_id = "none"
    payload_hash = "none"
    
    content_to_hash = f"{index}{timestamp}{operation}{partition_id}{payload_hash}{prev_hash}"
    block_hash = hashlib.sha256(content_to_hash.encode("utf-8")).hexdigest()
    
    block = {
        "index": index,
        "timestamp": timestamp,
        "operation": operation,
        "partition_id": partition_id,
        "payload_hash": payload_hash,
        "prev_hash": prev_hash,
        "hash": block_hash
    }
    
    ledger.append(block)
    
    with open(LEDGER_PATH, "w") as f:
        json.dump(ledger, f, indent=2)
        
    return "Success: Vault database reset. Genesis block initialized."

if __name__ == "__main__":
    mcp.run()
