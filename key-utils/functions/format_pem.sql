-- Re-wrap stripped base64 key material with PEM headers.
--
-- Takes raw base64 key material (as returned by GENERATE_RSA_KEY_PAIR or
-- STRIP_PEM_HEADERS) and wraps it with the appropriate PEM header/footer
-- and 64-character line breaks per the PEM standard (RFC 7468).
--
-- Parameters:
--   STRIPPED_KEY - Raw base64 key material (no PEM headers)
--   KEY_TYPE     - One of: 'PUBLIC KEY', 'PRIVATE KEY', 'RSA PUBLIC KEY',
--                  'RSA PRIVATE KEY', 'CERTIFICATE' (default: 'PUBLIC KEY')
--
-- Returns: Full PEM-formatted string.
--
-- Example:
--   SELECT FORMAT_PEM('MIIBIjANBgkq...', 'PUBLIC KEY');

CREATE OR REPLACE SECURE FUNCTION FORMAT_PEM(STRIPPED_KEY VARCHAR, KEY_TYPE VARCHAR DEFAULT 'PUBLIC KEY')
RETURNS VARCHAR
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
HANDLER = 'format_pem'
COMMENT = 'Re-wrap stripped base64 key material with PEM headers and 64-character line breaks. KEY_TYPE values: PUBLIC KEY, PRIVATE KEY, RSA PUBLIC KEY, RSA PRIVATE KEY, CERTIFICATE.'
AS
$$
def format_pem(stripped_key, key_type):
    """Wrap raw base64 key material in PEM headers with 64-char lines."""
    if stripped_key is None:
        return None

    key_type = (key_type or "PUBLIC KEY").upper()
    allowed_types = ("PUBLIC KEY", "PRIVATE KEY", "RSA PUBLIC KEY", "RSA PRIVATE KEY", "CERTIFICATE")
    if key_type not in allowed_types:
        return f"ERROR: KEY_TYPE must be one of: {', '.join(allowed_types)}"

    cleaned = stripped_key.replace("\n", "").replace("\r", "").replace(" ", "")
    lines = [cleaned[i:i+64] for i in range(0, len(cleaned), 64)]

    return (
        f"-----BEGIN {key_type}-----\n"
        + "\n".join(lines)
        + f"\n-----END {key_type}-----"
    )
$$;
