-- Rotate RSA key-pair authentication for a Snowflake service account,
-- storing the private key in Azure Key Vault.
--
-- Prerequisites (uncomment and adapt to your environment):
--
-- CREATE OR REPLACE NETWORK RULE NR_AZURE_KEY_VAULT
--     MODE = EGRESS
--     TYPE = HOST_PORT
--     VALUE_LIST = ('<vault-name>.vault.azure.net:443', 'login.microsoftonline.com:443');
--
-- CREATE OR REPLACE SECRET SK_AZURE_CREDENTIALS
--     TYPE = GENERIC_STRING
--     SECRET_STRING = '{"tenant_id": "...", "client_id": "...", "client_secret": "..."}';
--
-- CREATE OR REPLACE EXTERNAL ACCESS INTEGRATION EAI_AZURE_KEY_VAULT
--     ALLOWED_NETWORK_RULES = (NR_AZURE_KEY_VAULT)
--     ALLOWED_AUTHENTICATION_SECRETS = (SK_AZURE_CREDENTIALS)
--     ENABLED = TRUE;
--
-- Usage:
--   CALL ROTATE_KEYS_AZURE('SVC_DATA_PIPELINE', 'my-keyvault', 'snowflake-svc-data-pipeline-pk');
--   CALL ROTATE_KEYS_AZURE('SVC_DATA_PIPELINE', 'my-keyvault', 'snowflake-svc-data-pipeline-pk', 2048, TRUE);

CREATE OR REPLACE PROCEDURE ROTATE_KEYS_AZURE(
    TARGET_USER VARCHAR,
    VAULT_NAME VARCHAR,
    SECRET_NAME VARCHAR,
    KEY_SIZE_BITS NUMBER DEFAULT 2048,
    PROMOTE BOOLEAN DEFAULT FALSE
)
RETURNS VARIANT
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
PACKAGES = ('snowflake-snowpark-python', 'azure-identity', 'azure-keyvault-secrets')
HANDLER = 'rotate_keys_azure'
EXTERNAL_ACCESS_INTEGRATIONS = (EAI_AZURE_KEY_VAULT)
SECRETS = ('azure_creds' = SK_AZURE_CREDENTIALS)
EXECUTE AS CALLER
COMMENT = 'Rotate key-pair auth for a Snowflake user. Generates a new RSA key pair, assigns the public key, and stores the private key in Azure Key Vault.'
AS
$$
import json
import _snowflake
from azure.identity import ClientSecretCredential
from azure.keyvault.secrets import SecretClient

def rotate_keys_azure(session, target_user, vault_name, secret_name, key_size_bits, promote):
    # Generate and validate
    kp = json.loads(session.sql(f"SELECT GENERATE_RSA_KEY_PAIR({int(key_size_bits)})").collect()[0][0])
    if kp.get("error"):
        return {"success": False, "error": kp["error"]}

    validation = json.loads(session.sql(f"SELECT VALIDATE_RSA_PUBLIC_KEY('{kp['public_key']}')").collect()[0][0])
    if not validation["valid"]:
        return {"success": False, "error": validation["error"]}

    fingerprint = session.sql(f"SELECT FINGERPRINT_KEY('{kp['public_key']}', 'SHA256')").collect()[0][0]

    # Assign public key
    slot = "RSA_PUBLIC_KEY" if promote else "RSA_PUBLIC_KEY_2"
    session.sql(f"ALTER USER {target_user} SET {slot} = '{kp['public_key']}'").collect()

    # Push private key to Azure Key Vault
    creds = json.loads(_snowflake.get_generic_secret_string("azure_creds"))
    credential = ClientSecretCredential(
        tenant_id=creds["tenant_id"],
        client_id=creds["client_id"],
        client_secret=creds["client_secret"],
    )
    vault_url = f"https://{vault_name}.vault.azure.net"
    client = SecretClient(vault_url=vault_url, credential=credential)
    client.set_secret(secret_name, kp["private_key"])

    return {
        "success": True,
        "user": target_user,
        "key_slot": slot,
        "key_size": int(key_size_bits),
        "fingerprint": fingerprint,
        "vault": vault_url,
        "secret_name": secret_name,
    }
$$;
