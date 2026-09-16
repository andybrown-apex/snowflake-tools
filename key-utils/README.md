# Snowflake Key Management UDFs

RSA key pair generation, validation, and PEM formatting as Snowflake Python UDFs. Generate keys, assign them to service accounts, and validate them — all without leaving Snowflake.

## Why

Snowflake's key-pair authentication requires RSA keys in a specific format: base64-encoded, no PEM headers, no line breaks. Managing this typically means shelling out to `openssl`, copying keys between systems, and hoping nothing gets corrupted in transit.

These UDFs let you generate, validate, format, and fingerprint RSA keys directly inside Snowflake. Keys are created in memory on Snowflake compute and never touch disk or leave your account.

## Functions

| Function | File | Purpose |
|----------|------|---------|
| `GENERATE_RSA_KEY_PAIR` | [generate_rsa_key_pair.sql](functions/generate_rsa_key_pair.sql) | Generate a 2048, 3072, or 4096-bit RSA key pair |
| `VALIDATE_RSA_PUBLIC_KEY` | [validate_rsa_public_key.sql](functions/validate_rsa_public_key.sql) | Parse and validate an RSA public key |
| `FINGERPRINT_KEY` | [fingerprint_key.sql](functions/fingerprint_key.sql) | SHA-256 or SHA-1 fingerprint of key material |
| `STRIP_PEM_HEADERS` | [strip_pem_headers.sql](functions/strip_pem_headers.sql) | Remove PEM `-----BEGIN/END-----` wrapper lines |
| `FORMAT_PEM` | [format_pem.sql](functions/format_pem.sql) | Re-wrap stripped key material with PEM headers |

## Quick Start

Run any SQL file to create the function in your current database and schema:

```sql
-- Create all five functions
-- (run each .sql file in the functions/ directory)
```

Or paste them into a Snowflake worksheet and execute.

## Usage Examples

### Generate a key pair and assign it to a service account

```sql
-- Generate
SELECT GENERATE_RSA_KEY_PAIR(2048) AS KP;

-- Extract the public key and assign to a user
SET PUBLIC_KEY = (
    SELECT KP:public_key::VARCHAR
    FROM (SELECT GENERATE_RSA_KEY_PAIR(2048) AS KP)
);

ALTER USER MY_SERVICE_ACCOUNT SET RSA_PUBLIC_KEY = $PUBLIC_KEY;
```

### Store the private key as a Snowflake secret

```sql
-- Generate and store in one step
SET KP = (SELECT GENERATE_RSA_KEY_PAIR(2048));

CREATE SECRET MY_DB.MY_SCHEMA.SK_SERVICE_ACCOUNT_KEY
    TYPE = GENERIC_STRING
    SECRET_STRING = $KP:private_key::VARCHAR
    COMMENT = 'Private key for MY_SERVICE_ACCOUNT';
```

### Validate a public key before assigning it

```sql
SELECT VALIDATE_RSA_PUBLIC_KEY('MIIBIjANBgkq...');

-- Returns:
-- {
--   "valid": true,
--   "key_size": 2048,
--   "public_exponent": 65537,
--   "error": null
-- }
```

### Fingerprint a key for tracking

```sql
SELECT FINGERPRINT_KEY('MIIBIjANBgkq...', 'SHA256');
-- Returns: "a1b2c3d4e5f6..."
```

### Round-trip PEM formatting

```sql
-- Strip headers from a full PEM key
SELECT STRIP_PEM_HEADERS('-----BEGIN PUBLIC KEY-----
MIIBIjANBgkq...
-----END PUBLIC KEY-----');

-- Re-wrap stripped material back to PEM format
SELECT FORMAT_PEM('MIIBIjANBgkq...', 'PUBLIC KEY');
```

### End-to-end: generate, validate, fingerprint

```sql
WITH KEY_PAIR AS (
    SELECT GENERATE_RSA_KEY_PAIR(2048) AS KP
)
SELECT
    KP:public_key::VARCHAR AS PUBLIC_KEY
    ,KP:key_size_bits::NUMBER AS KEY_SIZE
    ,VALIDATE_RSA_PUBLIC_KEY(KP:public_key::VARCHAR):valid::BOOLEAN AS IS_VALID
    ,FINGERPRINT_KEY(KP:public_key::VARCHAR, 'SHA256') AS FINGERPRINT
FROM KEY_PAIR;
```

## Requirements

- Snowflake account with Python UDF support (Standard Edition or higher)
- Python runtime 3.11 (specified in each function)
- `cryptography` package (available on Snowflake's Anaconda channel — no setup needed)

`STRIP_PEM_HEADERS`, `FORMAT_PEM`, and `FINGERPRINT_KEY` use only Python standard library modules and have no external package dependency.

## Security Notes

- Keys are generated in memory on Snowflake compute nodes and returned as query results. They are never written to disk or stages.
- All functions are created with `SECURE` to prevent definition inspection by non-owners.
- The private key is returned in the query result. Treat it with the same care as any private key — store it as a Snowflake secret or retrieve it in a secure client session.
- These functions do not store, log, or transmit any key material.

## License

MIT
