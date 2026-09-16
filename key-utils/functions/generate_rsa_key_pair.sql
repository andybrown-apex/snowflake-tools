-- Generate an RSA key pair inside Snowflake.
--
-- Returns an OBJECT with:
--   public_key   - Base64-encoded public key (PEM headers stripped)
--   private_key  - Base64-encoded private key (PEM headers stripped)
--   key_size_bits - The key size used (2048, 3072, or 4096)
--   algorithm    - "RSA"
--   format       - "PKCS8"
--
-- The stripped format is what Snowflake expects for ALTER USER ... SET RSA_PUBLIC_KEY.
--
-- Example:
--   SELECT GENERATE_RSA_KEY_PAIR(2048);
--
--   SELECT
--       KP:public_key::VARCHAR  AS PUBLIC_KEY
--       ,KP:private_key::VARCHAR AS PRIVATE_KEY
--   FROM (SELECT GENERATE_RSA_KEY_PAIR(2048) AS KP);

CREATE OR REPLACE SECURE FUNCTION GENERATE_RSA_KEY_PAIR(KEY_SIZE_BITS NUMBER DEFAULT 2048)
RETURNS VARIANT
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
PACKAGES = ('cryptography')
HANDLER = 'generate_rsa_key_pair'
COMMENT = 'Generate an RSA key pair. Returns OBJECT with public_key and private_key (PEM headers stripped for Snowflake compatibility). Supported key sizes: 2048, 3072, 4096.'
AS
$$
def generate_rsa_key_pair(key_size_bits):
    """Generate an RSA key pair in memory and return stripped PEM material."""
    key_size = int(key_size_bits)
    if key_size not in (2048, 3072, 4096):
        return {"error": "KEY_SIZE_BITS must be 2048, 3072, or 4096", "public_key": None, "private_key": None}

    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")

    def strip_pem(pem):
        return "".join(
            line for line in pem.splitlines()
            if not line.startswith("-----")
        )

    return {
        "public_key": strip_pem(public_pem),
        "private_key": strip_pem(private_pem),
        "key_size_bits": key_size,
        "algorithm": "RSA",
        "format": "PKCS8",
    }
$$;
