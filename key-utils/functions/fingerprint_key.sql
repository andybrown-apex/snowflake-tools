-- Compute a hex-encoded fingerprint of key material.
--
-- Accepts stripped (no PEM headers) or raw base64 key material.
-- Decodes the base64 to raw bytes, then hashes with the specified algorithm.
--
-- Parameters:
--   KEY_MATERIAL - Base64-encoded key material (public or private)
--   ALGORITHM    - 'SHA256' (default) or 'SHA1'
--
-- Returns: Hex-encoded fingerprint string.
--
-- Example:
--   SELECT FINGERPRINT_KEY('MIIBIjANBgkq...', 'SHA256');

CREATE OR REPLACE SECURE FUNCTION FINGERPRINT_KEY(KEY_MATERIAL VARCHAR, ALGORITHM VARCHAR DEFAULT 'SHA256')
RETURNS VARCHAR
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
HANDLER = 'fingerprint_key'
COMMENT = 'Compute a hex-encoded fingerprint of key material. Accepts stripped (no PEM headers) or raw base64 key material. Supported algorithms: SHA256, SHA1.'
AS
$$
import hashlib
import base64

def fingerprint_key(key_material, algorithm):
    """Compute a fingerprint of the provided key material."""
    algorithm = (algorithm or "SHA256").upper()
    if algorithm not in ("SHA256", "SHA1"):
        return "ERROR: ALGORITHM must be SHA256 or SHA1"

    if key_material is None or len(key_material.strip()) == 0:
        return "ERROR: KEY_MATERIAL is empty"

    cleaned = key_material.replace("\n", "").replace("\r", "").replace(" ", "")
    try:
        raw_bytes = base64.b64decode(cleaned)
    except Exception:
        return "ERROR: KEY_MATERIAL is not valid base64"

    if algorithm == "SHA256":
        digest = hashlib.sha256(raw_bytes).hexdigest()
    else:
        digest = hashlib.sha1(raw_bytes).hexdigest()

    return digest
$$;
