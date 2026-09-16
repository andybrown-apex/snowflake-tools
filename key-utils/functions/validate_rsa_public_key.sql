-- Parse and validate an RSA public key.
--
-- Accepts stripped (no PEM headers) base64 key material, decodes it, and
-- attempts to parse it as an RSA public key using the cryptography library.
--
-- Returns an OBJECT with:
--   valid           - BOOLEAN: whether the key is a valid RSA public key
--   key_size        - NUMBER: key size in bits (e.g., 2048, 4096)
--   public_exponent - NUMBER: the public exponent (typically 65537)
--   error           - VARCHAR: error message if invalid, NULL if valid
--
-- Example:
--   SELECT VALIDATE_RSA_PUBLIC_KEY('MIIBIjANBgkq...');
--
--   -- Check before assigning to a user:
--   SELECT v:valid::BOOLEAN AS IS_VALID, v:key_size::NUMBER AS KEY_SIZE
--   FROM (SELECT VALIDATE_RSA_PUBLIC_KEY('MIIBIjANBgkq...') AS v);

CREATE OR REPLACE SECURE FUNCTION VALIDATE_RSA_PUBLIC_KEY(KEY_MATERIAL VARCHAR)
RETURNS VARIANT
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
PACKAGES = ('cryptography')
HANDLER = 'validate_rsa_public_key'
COMMENT = 'Parse and validate an RSA public key. Accepts stripped (no PEM headers) base64 material. Returns OBJECT with valid (BOOLEAN), key_size (NUMBER), public_exponent (NUMBER), and error (VARCHAR or NULL).'
AS
$$
import base64

def validate_rsa_public_key(key_material):
    """Parse an RSA public key and return metadata about it."""
    if key_material is None or len(key_material.strip()) == 0:
        return {"valid": False, "key_size": None, "public_exponent": None, "error": "KEY_MATERIAL is empty"}

    from cryptography.hazmat.primitives.serialization import load_der_public_key
    from cryptography.hazmat.primitives.asymmetric import rsa as rsa_module

    cleaned = key_material.replace("\n", "").replace("\r", "").replace(" ", "")
    try:
        der_bytes = base64.b64decode(cleaned)
    except Exception as exc:
        return {"valid": False, "key_size": None, "public_exponent": None, "error": f"Invalid base64: {str(exc)}"}

    try:
        public_key = load_der_public_key(der_bytes)
    except Exception as exc:
        return {"valid": False, "key_size": None, "public_exponent": None, "error": f"Cannot parse key: {str(exc)}"}

    if not isinstance(public_key, rsa_module.RSAPublicKey):
        return {"valid": False, "key_size": None, "public_exponent": None, "error": "Key is not an RSA public key"}

    return {
        "valid": True,
        "key_size": public_key.key_size,
        "public_exponent": public_key.public_numbers().e,
        "error": None,
    }
$$;
