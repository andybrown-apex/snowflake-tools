-- Remove PEM header and footer lines from key or certificate material.
--
-- Strips the -----BEGIN/END----- wrapper lines and returns the raw base64
-- content as a single continuous string. This is the format Snowflake
-- expects for RSA_PUBLIC_KEY and RSA_PUBLIC_KEY_2 parameters.
--
-- Parameters:
--   PEM_TEXT - Full PEM-encoded key or certificate (with headers)
--
-- Returns: Raw base64 string without headers, footers, or line breaks.
--
-- Example:
--   SELECT STRIP_PEM_HEADERS('-----BEGIN PUBLIC KEY-----
--   MIIBIjANBgkq...
--   -----END PUBLIC KEY-----');

CREATE OR REPLACE SECURE FUNCTION STRIP_PEM_HEADERS(PEM_TEXT VARCHAR)
RETURNS VARCHAR
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
HANDLER = 'strip_pem_headers'
COMMENT = 'Remove PEM header and footer lines (-----BEGIN/END-----) from PEM-encoded key or certificate material. Returns the raw base64 content as a single continuous string.'
AS
$$
def strip_pem_headers(pem_text):
    """Remove PEM header/footer lines and return continuous base64."""
    if pem_text is None:
        return None
    return "".join(
        line for line in pem_text.splitlines()
        if not line.startswith("-----")
    )
$$;
