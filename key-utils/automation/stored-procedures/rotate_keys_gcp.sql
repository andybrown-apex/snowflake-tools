-- Rotate RSA key-pair authentication for a Snowflake service account,
-- storing the private key in Google Cloud Secret Manager.
--
-- Prerequisites (uncomment and adapt to your environment):
--
-- CREATE OR REPLACE NETWORK RULE NR_GCP_SECRET_MANAGER
--     MODE = EGRESS
--     TYPE = HOST_PORT
--     VALUE_LIST = ('secretmanager.googleapis.com:443', 'oauth2.googleapis.com:443');
--
-- CREATE OR REPLACE SECRET SK_GCP_CREDENTIALS
--     TYPE = GENERIC_STRING
--     SECRET_STRING = '<service-account-key-json>';
--
-- CREATE OR REPLACE EXTERNAL ACCESS INTEGRATION EAI_GCP_SECRET_MANAGER
--     ALLOWED_NETWORK_RULES = (NR_GCP_SECRET_MANAGER)
--     ALLOWED_AUTHENTICATION_SECRETS = (SK_GCP_CREDENTIALS)
--     ENABLED = TRUE;
--
-- Usage:
--   CALL ROTATE_KEYS_GCP('SVC_DATA_PIPELINE', 'my-gcp-project', 'snowflake-svc-data-pipeline-pk');
--   CALL ROTATE_KEYS_GCP('SVC_DATA_PIPELINE', 'my-gcp-project', 'snowflake-svc-data-pipeline-pk', 2048, TRUE);

CREATE OR REPLACE PROCEDURE ROTATE_KEYS_GCP(
    TARGET_USER VARCHAR,
    GCP_PROJECT VARCHAR,
    SECRET_ID VARCHAR,
    KEY_SIZE_BITS NUMBER DEFAULT 2048,
    PROMOTE BOOLEAN DEFAULT FALSE
)
RETURNS VARIANT
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
PACKAGES = ('snowflake-snowpark-python', 'google-cloud-secret-manager')
HANDLER = 'rotate_keys_gcp'
EXTERNAL_ACCESS_INTEGRATIONS = (EAI_GCP_SECRET_MANAGER)
SECRETS = ('gcp_creds' = SK_GCP_CREDENTIALS)
EXECUTE AS CALLER
COMMENT = 'Rotate key-pair auth for a Snowflake user. Generates a new RSA key pair, assigns the public key, and stores the private key in Google Cloud Secret Manager.'
AS
$$
import json
import _snowflake
from google.oauth2 import service_account
from google.cloud import secretmanager

def rotate_keys_gcp(session, target_user, gcp_project, secret_id, key_size_bits, promote):
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

    # Push private key to Google Cloud Secret Manager
    creds_json = json.loads(_snowflake.get_generic_secret_string("gcp_creds"))
    credentials = service_account.Credentials.from_service_account_info(creds_json)
    client = secretmanager.SecretManagerServiceClient(credentials=credentials)
    secret_path = f"projects/{gcp_project}/secrets/{secret_id}"

    try:
        client.get_secret(request={"name": secret_path})
    except Exception:
        client.create_secret(
            request={
                "parent": f"projects/{gcp_project}",
                "secret_id": secret_id,
                "secret": {"replication": {"automatic": {}}},
            }
        )

    client.add_secret_version(
        request={
            "parent": secret_path,
            "payload": {"data": kp["private_key"].encode("utf-8")},
        }
    )

    return {
        "success": True,
        "user": target_user,
        "key_slot": slot,
        "key_size": int(key_size_bits),
        "fingerprint": fingerprint,
        "secret_path": secret_path,
    }
$$;
