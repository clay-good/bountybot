"""
CLI for secrets management.

Provides command-line interface for managing secrets.
"""

import sys
import argparse
import logging
from typing import Optional

from .secrets_manager import SecretsManager, SecretNotFoundError
from .models import SecretType

logger = logging.getLogger(__name__)


def create_secret_command(args):
    """Create a new secret."""
    manager = SecretsManager(
        vault_path=args.vault_path,
        master_key=args.master_key
    )
    
    try:
        secret = manager.create_secret(
            secret_id=args.secret_id,
            value=args.value,
            secret_type=SecretType(args.type),
            description=args.description,
            created_by=args.user
        )
        
        print(f"✓ Created secret: {secret.metadata.secret_id}")
        print(f"  Type: {secret.metadata.secret_type.value}")
        print(f"  Version: {secret.current_version}")
        
    except Exception as e:
        print(f"✗ Failed to create secret: {e}", file=sys.stderr)
        sys.exit(1)


def get_secret_command(args):
    """Get a secret value."""
    manager = SecretsManager(
        vault_path=args.vault_path,
        master_key=args.master_key
    )
    
    try:
        value = manager.get_secret(args.secret_id, accessed_by=args.user)
        
        if args.show_value:
            print(value)
        else:
            print(f"✓ Retrieved secret: {args.secret_id}")
            print(f"  Value: {value[:20]}..." if len(value) > 20 else f"  Value: {value}")
        
    except SecretNotFoundError as e:
        print(f"✗ {e}", file=sys.stderr)
        sys.exit(1)


def update_secret_command(args):
    """Update a secret."""
    manager = SecretsManager(
        vault_path=args.vault_path,
        master_key=args.master_key
    )
    
    try:
        secret = manager.update_secret(
            args.secret_id,
            args.value,
            updated_by=args.user
        )
        
        print(f"✓ Updated secret: {secret.metadata.secret_id}")
        print(f"  New version: {secret.current_version}")
        
    except SecretNotFoundError as e:
        print(f"✗ {e}", file=sys.stderr)
        sys.exit(1)


def delete_secret_command(args):
    """Delete a secret."""
    manager = SecretsManager(
        vault_path=args.vault_path,
        master_key=args.master_key
    )
    
    try:
        manager.delete_secret(args.secret_id, deleted_by=args.user)
        print(f"✓ Deleted secret: {args.secret_id}")
        
    except SecretNotFoundError as e:
        print(f"✗ {e}", file=sys.stderr)
        sys.exit(1)


def list_secrets_command(args):
    """List all secrets."""
    manager = SecretsManager(
        vault_path=args.vault_path,
        master_key=args.master_key
    )
    
    secrets = manager.list_secrets()
    
    if not secrets:
        print("No secrets found")
        return
    
    print(f"Total secrets: {len(secrets)}")
    for secret_id in sorted(secrets):
        print(f"  - {secret_id}")


def rotate_secret_command(args):
    """Rotate a secret."""
    manager = SecretsManager(
        vault_path=args.vault_path,
        master_key=args.master_key
    )
    
    try:
        secret = manager.rotate_secret(args.secret_id, rotated_by=args.user)
        
        print(f"✓ Rotated secret: {secret.metadata.secret_id}")
        print(f"  New version: {secret.current_version}")
        
        if args.show_value:
            print(f"  New value: {secret.current_value}")
        
    except (SecretNotFoundError, NotImplementedError) as e:
        print(f"✗ {e}", file=sys.stderr)
        sys.exit(1)


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description='BountyBot Secrets Management CLI',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        '--vault-path',
        help='Path to local vault directory',
        default=None
    )
    
    parser.add_argument(
        '--master-key',
        help='Master encryption key',
        default=None
    )
    
    parser.add_argument(
        '--user',
        help='User performing the operation',
        default='cli'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Create command
    create_parser = subparsers.add_parser('create', help='Create a new secret')
    create_parser.add_argument('secret_id', help='Secret identifier')
    create_parser.add_argument('value', help='Secret value')
    create_parser.add_argument(
        '--type',
        choices=[t.value for t in SecretType],
        default='generic',
        help='Secret type'
    )
    create_parser.add_argument('--description', help='Secret description')
    create_parser.set_defaults(func=create_secret_command)
    
    # Get command
    get_parser = subparsers.add_parser('get', help='Get a secret value')
    get_parser.add_argument('secret_id', help='Secret identifier')
    get_parser.add_argument(
        '--show-value',
        action='store_true',
        help='Show full secret value'
    )
    get_parser.set_defaults(func=get_secret_command)
    
    # Update command
    update_parser = subparsers.add_parser('update', help='Update a secret')
    update_parser.add_argument('secret_id', help='Secret identifier')
    update_parser.add_argument('value', help='New secret value')
    update_parser.set_defaults(func=update_secret_command)
    
    # Delete command
    delete_parser = subparsers.add_parser('delete', help='Delete a secret')
    delete_parser.add_argument('secret_id', help='Secret identifier')
    delete_parser.set_defaults(func=delete_secret_command)
    
    # List command
    list_parser = subparsers.add_parser('list', help='List all secrets')
    list_parser.set_defaults(func=list_secrets_command)
    
    # Rotate command
    rotate_parser = subparsers.add_parser('rotate', help='Rotate a secret')
    rotate_parser.add_argument('secret_id', help='Secret identifier')
    rotate_parser.add_argument(
        '--show-value',
        action='store_true',
        help='Show new secret value'
    )
    rotate_parser.set_defaults(func=rotate_secret_command)
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # Execute command
    args.func(args)


if __name__ == '__main__':
    main()

