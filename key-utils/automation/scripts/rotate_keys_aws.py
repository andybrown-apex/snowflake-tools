"""Rotate RSA key-pair authentication for a Snowflake service account.

Generates a new key pair in Snowflake, assigns the public key, and stores
the private key in AWS Secrets Manager.

Requires:
    pip install snowflake-connector-python boto3

Usage:
    python rotate_keys_aws.py --user SVC_DATA_PIPELINE \
        --secret-id snowflake/svc_data_pipeline/private_key \
        --connection-name my_connection

    # With explicit Snowflake credentials:
    python rotate_keys_aws.py --user SVC_DATA_PIPELINE \
        --secret-id snowflake/svc_data_pipeline/private_key \
        --account xy12345.us-east-1 --sf-user ADMIN --sf-role SECURITYADMIN

    # Promote immediately (skip dual-slot staging):
    python rotate_keys_aws.py --user SVC_DATA_PIPELINE \
        --secret-id snowflake/svc_data_pipeline/private_key \
        --promote
"""

import argparse
import json
import sys

import boto3
import snowflake.connector


def connect_snowflake(args):
    params = {}
    if args.connection_name:
        params["connection_name"] = args.connection_name
    else:
        params["account"] = args.account
        params["user"] = args.sf_user
        params["role"] = args.sf_role
        if args.authenticator:
            params["authenticator"] = args.authenticator
    return snowflake.connector.connect(**params)


def rotate(args):
    ctx = connect_snowflake(args)
    cs = ctx.cursor()

    try:
        # Generate and validate
        cs.execute(f"SELECT GENERATE_RSA_KEY_PAIR({args.key_size})")
        kp = json.loads(cs.fetchone()[0])
        if kp.get("error"):
            print(f"Key generation failed: {kp['error']}", file=sys.stderr)
            return 1

        cs.execute("SELECT VALIDATE_RSA_PUBLIC_KEY(%s)", (kp["public_key"],))
        validation = json.loads(cs.fetchone()[0])
        if not validation["valid"]:
            print(f"Key validation failed: {validation['error']}", file=sys.stderr)
            return 1

        cs.execute("SELECT FINGERPRINT_KEY(%s, 'SHA256')", (kp["public_key"],))
        fingerprint = cs.fetchone()[0]

        # Assign public key
        slot = "RSA_PUBLIC_KEY" if args.promote else "RSA_PUBLIC_KEY_2"
        cs.execute(f"ALTER USER {args.user} SET {slot} = %s", (kp["public_key"],))

        # Push private key to AWS Secrets Manager
        sm = boto3.client("secretsmanager", region_name=args.region)
        try:
            sm.put_secret_value(
                SecretId=args.secret_id,
                SecretString=kp["private_key"],
            )
        except sm.exceptions.ResourceNotFoundException:
            sm.create_secret(
                Name=args.secret_id,
                SecretString=kp["private_key"],
            )

        print(f"User:        {args.user}")
        print(f"Key slot:    {slot}")
        print(f"Key size:    {args.key_size}")
        print(f"Fingerprint: {fingerprint}")
        print(f"Secret:      {args.secret_id}")
        if not args.promote:
            print(f"\nKey staged in {slot}. After verifying connectivity, promote with:")
            print(f"  ALTER USER {args.user} SET RSA_PUBLIC_KEY = '<public_key>';")
            print(f"  ALTER USER {args.user} UNSET RSA_PUBLIC_KEY_2;")
        return 0

    finally:
        cs.close()
        ctx.close()


def main():
    parser = argparse.ArgumentParser(description="Rotate Snowflake key-pair auth with AWS Secrets Manager")
    parser.add_argument("--user", required=True, help="Snowflake user to rotate keys for")
    parser.add_argument("--secret-id", required=True, help="AWS Secrets Manager secret ID for the private key")
    parser.add_argument("--key-size", type=int, default=2048, choices=[2048, 3072, 4096])
    parser.add_argument("--region", default=None, help="AWS region (defaults to boto3 session region)")
    parser.add_argument("--promote", action="store_true", help="Assign directly to RSA_PUBLIC_KEY instead of staging in slot 2")

    sf = parser.add_argument_group("Snowflake connection")
    sf.add_argument("--connection-name", help="Snowflake connection name (from connections.toml)")
    sf.add_argument("--account", help="Snowflake account identifier")
    sf.add_argument("--sf-user", help="Snowflake user for authentication")
    sf.add_argument("--sf-role", default="SECURITYADMIN", help="Snowflake role (default: SECURITYADMIN)")
    sf.add_argument("--authenticator", help="Snowflake authenticator (e.g. externalbrowser)")

    args = parser.parse_args()
    sys.exit(rotate(args))


if __name__ == "__main__":
    main()
