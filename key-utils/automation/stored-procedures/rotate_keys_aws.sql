-- Rotate RSA key-pair authentication for a Snowflake service account,
-- storing the private key in AWS Secrets Manager.
--
-- Prerequisites (uncomment and adapt to your environment):
--
-- CREATE OR REPLACE NETWORK RULE NR_AWS_SECRETS_MANAGER
--     MODE = EGRESS
--     TYPE = HOST_PORT
--     VALUE_LIST = ('secretsmanager.<region>.amazonaws.com:443');
--
-- CREATE OR REPLACE SECRET SK_AWS_CREDENTIALS
--     TYPE = GENERIC_STRING
--     SECRET_STRING = '{"aws_access_key_id": "...", "aws_secret_access_key": "..."}';
--
-- CREATE OR REPLACE EXTERNAL ACCESS INTEGRATION EAI_AWS_SECRETS_MANAGER
--     ALLOWED_NETWORK_RULES = (NR_AWS_SECRETS_MANAGER)
--     ALLOWED_AUTHENTICATION_SECRETS = (SK_AWS_CREDENTIALS)
--     ENABLED = TRUE;
--
-- Usage:
--   CALL ROTATE_KEYS_AWS('SVC_DATA_PIPELINE', 'snowflake/svc_data_pipeline/private_key', 'us-east-1');
--   CALL ROTATE_KEYS_AWS('SVC_DATA_PIPELINE', 'snowflake/svc_data_pipeline/private_key', 'us-east-1', 2048, TRUE);

CREATE OR REPLACE PROCEDURE ROTATE_KEYS_AWS(
    TARGET_USER VARCHAR,
    SECRET_ID VARCHAR,
    AWS_REGION VARCHAR,
    KEY_SIZE_BITS NUMBER DEFAULT 2048,
    PROMOTE BOOLEAN DEFAULT FALSE
)
RETURNS VARIANT
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
PACKAGES = ('snowflake-snowpark-python', 'boto3')
HANDLER = 'rotate_keys_aws'
EXTERNAL_ACCESS_INTEGRATIONS = (EAI_AWS_SECRETS_MANAGER)
SECRETS = ('aws_creds' = SK_AWS_CREDENTIALS)
EXECUTE AS CALLER
COMMENT = 'Rotate key-pair auth for a Snowflake user. Generates a new RSA key pair, assigns the public key, and stores the private key in AWS Secrets Manager.'
AS
$$
import json
import boto3
import _snowflake

def rotate_keys_aws(session, target_user, secret_id, aws_region, key_size_bits, promote):
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

    # Push private key to AWS Secrets Manager
    creds = json.loads(_snowflake.get_generic_secret_string("aws_creds"))
    sm = boto3.client(
        "secretsmanager",
        region_name=aws_region,
        aws_access_key_id=creds["aws_access_key_id"],
        aws_secret_access_key=creds["aws_secret_access_key"],
    )
    try:
        sm.put_secret_value(SecretId=secret_id, SecretString=kp["private_key"])
    except sm.exceptions.ResourceNotFoundException:
        sm.create_secret(Name=secret_id, SecretString=kp["private_key"])

    return {
        "success": True,
        "user": target_user,
        "key_slot": slot,
        "key_size": int(key_size_bits),
        "fingerprint": fingerprint,
        "secret_id": secret_id,
    }
$$;
