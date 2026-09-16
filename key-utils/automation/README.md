# Key Rotation Automation

Automate RSA key-pair rotation for Snowflake service accounts with private keys stored in an external vault. Available as standalone Python scripts (run from your machine or CI/CD) and as Snowflake stored procedures (run entirely inside Snowflake via external access integrations).

Both approaches use the [key-utils UDFs](../README.md) to generate, validate, and fingerprint keys inside Snowflake. The only difference is where the vault SDK call happens.

## Supported Providers

| Provider | Script | Stored Procedure |
|----------|--------|-----------------|
| AWS Secrets Manager | [rotate_keys_aws.py](scripts/rotate_keys_aws.py) | [rotate_keys_aws.sql](stored-procedures/rotate_keys_aws.sql) |
| Azure Key Vault | [rotate_keys_azure.py](scripts/rotate_keys_azure.py) | [rotate_keys_azure.sql](stored-procedures/rotate_keys_azure.sql) |
| Google Cloud Secret Manager | [rotate_keys_gcp.py](scripts/rotate_keys_gcp.py) | [rotate_keys_gcp.sql](stored-procedures/rotate_keys_gcp.sql) |

## How It Works

1. `GENERATE_RSA_KEY_PAIR()` creates a new key pair in Snowflake
2. `VALIDATE_RSA_PUBLIC_KEY()` confirms the key is valid before assignment
3. The public key is assigned to the user via `ALTER USER ... SET RSA_PUBLIC_KEY_2` (dual-slot staging by default)
4. The private key is pushed to your vault
5. `FINGERPRINT_KEY()` produces a SHA-256 fingerprint for audit logging
6. After verifying connectivity, promote the new key to the primary slot

## Python Scripts

### Prerequisites

```bash
# AWS
pip install snowflake-connector-python boto3

# Azure
pip install snowflake-connector-python azure-identity azure-keyvault-secrets

# GCP
pip install snowflake-connector-python google-cloud-secret-manager
```

### Usage

```bash
# AWS Secrets Manager
python rotate_keys_aws.py \
    --user SVC_DATA_PIPELINE \
    --secret-id snowflake/svc_data_pipeline/private_key \
    --connection-name my_connection

# Azure Key Vault
python rotate_keys_azure.py \
    --user SVC_DATA_PIPELINE \
    --vault-name my-keyvault \
    --secret-name snowflake-svc-data-pipeline-pk \
    --connection-name my_connection

# Google Cloud Secret Manager
python rotate_keys_gcp.py \
    --user SVC_DATA_PIPELINE \
    --project my-gcp-project \
    --secret-id snowflake-svc-data-pipeline-pk \
    --connection-name my_connection
```

By default, the new key is staged in `RSA_PUBLIC_KEY_2` so the existing key continues to work. Add `--promote` to assign directly to `RSA_PUBLIC_KEY`.

### Snowflake Connection Options

Each script supports two ways to connect to Snowflake:

- `--connection-name` — Uses a named connection from `connections.toml`
- `--account`, `--sf-user`, `--sf-role`, `--authenticator` — Explicit credentials

The role defaults to `SECURITYADMIN`, which has the privileges needed for `ALTER USER`.

## Stored Procedures

The stored procedures run entirely inside Snowflake using external access integrations to reach your vault's API. No external runner or CI/CD needed.

### Prerequisites

Each stored procedure requires three objects:

1. **[Network rule](https://docs.snowflake.com/en/sql-reference/sql/create-network-rule)** — Allows egress to your vault's API endpoint
2. **[Secret](https://docs.snowflake.com/en/sql-reference/sql/create-secret)** — Stores the cloud credentials Snowflake uses to authenticate with your vault
3. **[External access integration](https://docs.snowflake.com/en/sql-reference/sql/create-external-access-integration)** — Ties the network rule and secret together

For an overview of how these fit together, see [External network access](https://docs.snowflake.com/en/developer-guide/external-network-access/external-network-access-overview) in the Snowflake docs.

The setup SQL for each provider is included as comments at the top of each `.sql` file. Uncomment and adapt to your environment before creating the procedure.

You also need the [key-utils UDFs](../README.md) created in the same database/schema.

### Usage

```sql
-- AWS Secrets Manager
CALL ROTATE_KEYS_AWS('SVC_DATA_PIPELINE', 'snowflake/svc_data_pipeline/private_key', 'us-east-1');

-- Azure Key Vault
CALL ROTATE_KEYS_AZURE('SVC_DATA_PIPELINE', 'my-keyvault', 'snowflake-svc-data-pipeline-pk');

-- Google Cloud Secret Manager
CALL ROTATE_KEYS_GCP('SVC_DATA_PIPELINE', 'my-gcp-project', 'snowflake-svc-data-pipeline-pk');
```

To promote directly to the primary key slot instead of staging:

```sql
CALL ROTATE_KEYS_AWS('SVC_DATA_PIPELINE', 'snowflake/svc_data_pipeline/private_key', 'us-east-1', 2048, TRUE);
```

### Return Value

Each procedure returns a VARIANT object:

```json
{
  "success": true,
  "user": "SVC_DATA_PIPELINE",
  "key_slot": "RSA_PUBLIC_KEY_2",
  "key_size": 2048,
  "fingerprint": "a1b2c3d4e5f6..."
}
```

## Promoting a Staged Key

After verifying that your application connects successfully with the new key:

```sql
-- Move new key to primary slot and remove the staging slot
ALTER USER SVC_DATA_PIPELINE SET RSA_PUBLIC_KEY = '<new_public_key>';
ALTER USER SVC_DATA_PIPELINE UNSET RSA_PUBLIC_KEY_2;
```

## Testing Status

The stored procedures have been validated to compile, but have not been executed end-to-end. They depend on external access integrations, network rules, and secrets that are specific to each environment. You will need to create those prerequisite objects (documented at the top of each `.sql` file) and test in your own account.

The Python scripts follow the same logic and use standard SDK calls for each provider.

## Security Notes

- The stored procedures use `EXECUTE AS CALLER`, so the calling role must have privileges to `ALTER USER`.
- Cloud credentials stored in Snowflake secrets are accessed via `_snowflake.get_generic_secret_string()` and are never exposed in query results or logs.
- Key material exists only in memory during execution. Session variables should be unset after use (the scripts and procedures handle this automatically).
