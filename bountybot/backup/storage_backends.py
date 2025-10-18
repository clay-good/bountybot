"""
Storage Backends

Support for multiple backup storage backends:
- Local filesystem
- AWS S3
- Google Cloud Storage
- Azure Blob Storage
"""

import os
import logging
import shutil
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional, List, BinaryIO
from datetime import datetime

logger = logging.getLogger(__name__)


class StorageBackend(ABC):
    """Abstract base class for storage backends."""
    
    @abstractmethod
    def upload(self, local_path: str, remote_path: str) -> bool:
        """
        Upload a file to storage.
        
        Args:
            local_path: Path to local file
            remote_path: Path in remote storage
            
        Returns:
            True if successful, False otherwise
        """
        pass
    
    @abstractmethod
    def download(self, remote_path: str, local_path: str) -> bool:
        """
        Download a file from storage.
        
        Args:
            remote_path: Path in remote storage
            local_path: Path to save locally
            
        Returns:
            True if successful, False otherwise
        """
        pass
    
    @abstractmethod
    def delete(self, remote_path: str) -> bool:
        """
        Delete a file from storage.
        
        Args:
            remote_path: Path in remote storage
            
        Returns:
            True if successful, False otherwise
        """
        pass
    
    @abstractmethod
    def exists(self, remote_path: str) -> bool:
        """
        Check if a file exists in storage.
        
        Args:
            remote_path: Path in remote storage
            
        Returns:
            True if exists, False otherwise
        """
        pass
    
    @abstractmethod
    def list_files(self, prefix: str = "") -> List[str]:
        """
        List files in storage.
        
        Args:
            prefix: Path prefix to filter by
            
        Returns:
            List of file paths
        """
        pass
    
    @abstractmethod
    def get_size(self, remote_path: str) -> int:
        """
        Get file size in bytes.
        
        Args:
            remote_path: Path in remote storage
            
        Returns:
            File size in bytes, or 0 if not found
        """
        pass
    
    @abstractmethod
    def get_metadata(self, remote_path: str) -> dict:
        """
        Get file metadata.
        
        Args:
            remote_path: Path in remote storage
            
        Returns:
            Dictionary with metadata
        """
        pass


class LocalStorageBackend(StorageBackend):
    """Local filesystem storage backend."""
    
    def __init__(self, base_path: str):
        """
        Initialize local storage backend.
        
        Args:
            base_path: Base directory for backups
        """
        self.base_path = Path(base_path)
        self.base_path.mkdir(parents=True, exist_ok=True)
        logger.info(f"Local storage backend initialized: {self.base_path}")
    
    def _get_full_path(self, remote_path: str) -> Path:
        """Get full local path."""
        return self.base_path / remote_path
    
    def upload(self, local_path: str, remote_path: str) -> bool:
        """Upload file to local storage."""
        try:
            dest_path = self._get_full_path(remote_path)
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(local_path, dest_path)
            logger.info(f"Uploaded {local_path} to {dest_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to upload {local_path}: {e}")
            return False
    
    def download(self, remote_path: str, local_path: str) -> bool:
        """Download file from local storage."""
        try:
            source_path = self._get_full_path(remote_path)
            Path(local_path).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_path, local_path)
            logger.info(f"Downloaded {source_path} to {local_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to download {remote_path}: {e}")
            return False
    
    def delete(self, remote_path: str) -> bool:
        """Delete file from local storage."""
        try:
            file_path = self._get_full_path(remote_path)
            if file_path.exists():
                file_path.unlink()
                logger.info(f"Deleted {file_path}")
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to delete {remote_path}: {e}")
            return False
    
    def exists(self, remote_path: str) -> bool:
        """Check if file exists in local storage."""
        return self._get_full_path(remote_path).exists()
    
    def list_files(self, prefix: str = "") -> List[str]:
        """List files in local storage."""
        try:
            search_path = self._get_full_path(prefix) if prefix else self.base_path
            if search_path.is_file():
                return [str(search_path.relative_to(self.base_path))]
            elif search_path.is_dir():
                return [
                    str(p.relative_to(self.base_path))
                    for p in search_path.rglob('*')
                    if p.is_file()
                ]
            return []
        except Exception as e:
            logger.error(f"Failed to list files with prefix {prefix}: {e}")
            return []
    
    def get_size(self, remote_path: str) -> int:
        """Get file size."""
        try:
            file_path = self._get_full_path(remote_path)
            if file_path.exists():
                return file_path.stat().st_size
            return 0
        except Exception as e:
            logger.error(f"Failed to get size of {remote_path}: {e}")
            return 0
    
    def get_metadata(self, remote_path: str) -> dict:
        """Get file metadata."""
        try:
            file_path = self._get_full_path(remote_path)
            if file_path.exists():
                stat = file_path.stat()
                return {
                    'size': stat.st_size,
                    'created': datetime.fromtimestamp(stat.st_ctime),
                    'modified': datetime.fromtimestamp(stat.st_mtime),
                    'path': str(file_path)
                }
            return {}
        except Exception as e:
            logger.error(f"Failed to get metadata for {remote_path}: {e}")
            return {}


class S3StorageBackend(StorageBackend):
    """AWS S3 storage backend."""
    
    def __init__(
        self,
        bucket_name: str,
        region: str = "us-east-1",
        access_key: Optional[str] = None,
        secret_key: Optional[str] = None,
        prefix: str = ""
    ):
        """
        Initialize S3 storage backend.
        
        Args:
            bucket_name: S3 bucket name
            region: AWS region
            access_key: AWS access key (optional, uses IAM role if not provided)
            secret_key: AWS secret key (optional)
            prefix: Key prefix for all backups
        """
        self.bucket_name = bucket_name
        self.region = region
        self.prefix = prefix
        
        try:
            import boto3
            
            if access_key and secret_key:
                self.s3_client = boto3.client(
                    's3',
                    region_name=region,
                    aws_access_key_id=access_key,
                    aws_secret_access_key=secret_key
                )
            else:
                # Use IAM role or environment credentials
                self.s3_client = boto3.client('s3', region_name=region)
            
            logger.info(f"S3 storage backend initialized: s3://{bucket_name}/{prefix}")
        except ImportError:
            raise ImportError("boto3 is required for S3 storage. Install with: pip install boto3")
        except Exception as e:
            raise RuntimeError(f"Failed to initialize S3 client: {e}")
    
    def _get_key(self, remote_path: str) -> str:
        """Get full S3 key."""
        if self.prefix:
            return f"{self.prefix}/{remote_path}"
        return remote_path

    def upload(self, local_path: str, remote_path: str) -> bool:
        """Upload file to S3."""
        try:
            key = self._get_key(remote_path)
            self.s3_client.upload_file(local_path, self.bucket_name, key)
            logger.info(f"Uploaded {local_path} to s3://{self.bucket_name}/{key}")
            return True
        except Exception as e:
            logger.error(f"Failed to upload {local_path} to S3: {e}")
            return False

    def download(self, remote_path: str, local_path: str) -> bool:
        """Download file from S3."""
        try:
            key = self._get_key(remote_path)
            Path(local_path).parent.mkdir(parents=True, exist_ok=True)
            self.s3_client.download_file(self.bucket_name, key, local_path)
            logger.info(f"Downloaded s3://{self.bucket_name}/{key} to {local_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to download {remote_path} from S3: {e}")
            return False

    def delete(self, remote_path: str) -> bool:
        """Delete file from S3."""
        try:
            key = self._get_key(remote_path)
            self.s3_client.delete_object(Bucket=self.bucket_name, Key=key)
            logger.info(f"Deleted s3://{self.bucket_name}/{key}")
            return True
        except Exception as e:
            logger.error(f"Failed to delete {remote_path} from S3: {e}")
            return False

    def exists(self, remote_path: str) -> bool:
        """Check if file exists in S3."""
        try:
            key = self._get_key(remote_path)
            self.s3_client.head_object(Bucket=self.bucket_name, Key=key)
            return True
        except:
            return False

    def list_files(self, prefix: str = "") -> List[str]:
        """List files in S3."""
        try:
            full_prefix = self._get_key(prefix) if prefix else self.prefix
            response = self.s3_client.list_objects_v2(
                Bucket=self.bucket_name,
                Prefix=full_prefix
            )

            if 'Contents' not in response:
                return []

            # Remove prefix from keys
            prefix_len = len(self.prefix) + 1 if self.prefix else 0
            return [obj['Key'][prefix_len:] for obj in response['Contents']]
        except Exception as e:
            logger.error(f"Failed to list files in S3: {e}")
            return []

    def get_size(self, remote_path: str) -> int:
        """Get file size from S3."""
        try:
            key = self._get_key(remote_path)
            response = self.s3_client.head_object(Bucket=self.bucket_name, Key=key)
            return response['ContentLength']
        except Exception as e:
            logger.error(f"Failed to get size of {remote_path} from S3: {e}")
            return 0

    def get_metadata(self, remote_path: str) -> dict:
        """Get file metadata from S3."""
        try:
            key = self._get_key(remote_path)
            response = self.s3_client.head_object(Bucket=self.bucket_name, Key=key)
            return {
                'size': response['ContentLength'],
                'modified': response['LastModified'],
                'etag': response['ETag'],
                'storage_class': response.get('StorageClass', 'STANDARD')
            }
        except Exception as e:
            logger.error(f"Failed to get metadata for {remote_path} from S3: {e}")
            return {}


class GCSStorageBackend(StorageBackend):
    """Google Cloud Storage backend."""

    def __init__(
        self,
        bucket_name: str,
        project_id: Optional[str] = None,
        credentials_path: Optional[str] = None,
        prefix: str = ""
    ):
        """
        Initialize GCS storage backend.

        Args:
            bucket_name: GCS bucket name
            project_id: GCP project ID (optional)
            credentials_path: Path to service account JSON (optional)
            prefix: Key prefix for all backups
        """
        self.bucket_name = bucket_name
        self.prefix = prefix

        try:
            from google.cloud import storage

            if credentials_path:
                self.client = storage.Client.from_service_account_json(
                    credentials_path,
                    project=project_id
                )
            else:
                self.client = storage.Client(project=project_id)

            self.bucket = self.client.bucket(bucket_name)
            logger.info(f"GCS storage backend initialized: gs://{bucket_name}/{prefix}")
        except ImportError:
            raise ImportError("google-cloud-storage is required for GCS. Install with: pip install google-cloud-storage")
        except Exception as e:
            raise RuntimeError(f"Failed to initialize GCS client: {e}")

    def _get_blob_name(self, remote_path: str) -> str:
        """Get full blob name."""
        if self.prefix:
            return f"{self.prefix}/{remote_path}"
        return remote_path

    def upload(self, local_path: str, remote_path: str) -> bool:
        """Upload file to GCS."""
        try:
            blob_name = self._get_blob_name(remote_path)
            blob = self.bucket.blob(blob_name)
            blob.upload_from_filename(local_path)
            logger.info(f"Uploaded {local_path} to gs://{self.bucket_name}/{blob_name}")
            return True
        except Exception as e:
            logger.error(f"Failed to upload {local_path} to GCS: {e}")
            return False

    def download(self, remote_path: str, local_path: str) -> bool:
        """Download file from GCS."""
        try:
            blob_name = self._get_blob_name(remote_path)
            blob = self.bucket.blob(blob_name)
            Path(local_path).parent.mkdir(parents=True, exist_ok=True)
            blob.download_to_filename(local_path)
            logger.info(f"Downloaded gs://{self.bucket_name}/{blob_name} to {local_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to download {remote_path} from GCS: {e}")
            return False

    def delete(self, remote_path: str) -> bool:
        """Delete file from GCS."""
        try:
            blob_name = self._get_blob_name(remote_path)
            blob = self.bucket.blob(blob_name)
            blob.delete()
            logger.info(f"Deleted gs://{self.bucket_name}/{blob_name}")
            return True
        except Exception as e:
            logger.error(f"Failed to delete {remote_path} from GCS: {e}")
            return False

    def exists(self, remote_path: str) -> bool:
        """Check if file exists in GCS."""
        try:
            blob_name = self._get_blob_name(remote_path)
            blob = self.bucket.blob(blob_name)
            return blob.exists()
        except:
            return False

    def list_files(self, prefix: str = "") -> List[str]:
        """List files in GCS."""
        try:
            full_prefix = self._get_blob_name(prefix) if prefix else self.prefix
            blobs = self.client.list_blobs(self.bucket_name, prefix=full_prefix)

            # Remove prefix from blob names
            prefix_len = len(self.prefix) + 1 if self.prefix else 0
            return [blob.name[prefix_len:] for blob in blobs]
        except Exception as e:
            logger.error(f"Failed to list files in GCS: {e}")
            return []

    def get_size(self, remote_path: str) -> int:
        """Get file size from GCS."""
        try:
            blob_name = self._get_blob_name(remote_path)
            blob = self.bucket.blob(blob_name)
            blob.reload()
            return blob.size
        except Exception as e:
            logger.error(f"Failed to get size of {remote_path} from GCS: {e}")
            return 0

    def get_metadata(self, remote_path: str) -> dict:
        """Get file metadata from GCS."""
        try:
            blob_name = self._get_blob_name(remote_path)
            blob = self.bucket.blob(blob_name)
            blob.reload()
            return {
                'size': blob.size,
                'created': blob.time_created,
                'modified': blob.updated,
                'content_type': blob.content_type,
                'storage_class': blob.storage_class
            }
        except Exception as e:
            logger.error(f"Failed to get metadata for {remote_path} from GCS: {e}")
            return {}


class AzureStorageBackend(StorageBackend):
    """Azure Blob Storage backend."""

    def __init__(
        self,
        container_name: str,
        account_name: Optional[str] = None,
        account_key: Optional[str] = None,
        connection_string: Optional[str] = None,
        prefix: str = ""
    ):
        """
        Initialize Azure storage backend.

        Args:
            container_name: Azure container name
            account_name: Storage account name (optional)
            account_key: Storage account key (optional)
            connection_string: Connection string (optional)
            prefix: Blob prefix for all backups
        """
        self.container_name = container_name
        self.prefix = prefix

        try:
            from azure.storage.blob import BlobServiceClient

            if connection_string:
                self.blob_service_client = BlobServiceClient.from_connection_string(connection_string)
            elif account_name and account_key:
                self.blob_service_client = BlobServiceClient(
                    account_url=f"https://{account_name}.blob.core.windows.net",
                    credential=account_key
                )
            else:
                raise ValueError("Either connection_string or (account_name and account_key) must be provided")

            self.container_client = self.blob_service_client.get_container_client(container_name)
            logger.info(f"Azure storage backend initialized: {container_name}/{prefix}")
        except ImportError:
            raise ImportError("azure-storage-blob is required for Azure. Install with: pip install azure-storage-blob")
        except Exception as e:
            raise RuntimeError(f"Failed to initialize Azure client: {e}")

    def _get_blob_name(self, remote_path: str) -> str:
        """Get full blob name."""
        if self.prefix:
            return f"{self.prefix}/{remote_path}"
        return remote_path

    def upload(self, local_path: str, remote_path: str) -> bool:
        """Upload file to Azure."""
        try:
            blob_name = self._get_blob_name(remote_path)
            blob_client = self.container_client.get_blob_client(blob_name)
            with open(local_path, 'rb') as data:
                blob_client.upload_blob(data, overwrite=True)
            logger.info(f"Uploaded {local_path} to Azure {self.container_name}/{blob_name}")
            return True
        except Exception as e:
            logger.error(f"Failed to upload {local_path} to Azure: {e}")
            return False

    def download(self, remote_path: str, local_path: str) -> bool:
        """Download file from Azure."""
        try:
            blob_name = self._get_blob_name(remote_path)
            blob_client = self.container_client.get_blob_client(blob_name)
            Path(local_path).parent.mkdir(parents=True, exist_ok=True)
            with open(local_path, 'wb') as download_file:
                download_file.write(blob_client.download_blob().readall())
            logger.info(f"Downloaded Azure {self.container_name}/{blob_name} to {local_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to download {remote_path} from Azure: {e}")
            return False

    def delete(self, remote_path: str) -> bool:
        """Delete file from Azure."""
        try:
            blob_name = self._get_blob_name(remote_path)
            blob_client = self.container_client.get_blob_client(blob_name)
            blob_client.delete_blob()
            logger.info(f"Deleted Azure {self.container_name}/{blob_name}")
            return True
        except Exception as e:
            logger.error(f"Failed to delete {remote_path} from Azure: {e}")
            return False

    def exists(self, remote_path: str) -> bool:
        """Check if file exists in Azure."""
        try:
            blob_name = self._get_blob_name(remote_path)
            blob_client = self.container_client.get_blob_client(blob_name)
            return blob_client.exists()
        except:
            return False

    def list_files(self, prefix: str = "") -> List[str]:
        """List files in Azure."""
        try:
            full_prefix = self._get_blob_name(prefix) if prefix else self.prefix
            blobs = self.container_client.list_blobs(name_starts_with=full_prefix)

            # Remove prefix from blob names
            prefix_len = len(self.prefix) + 1 if self.prefix else 0
            return [blob.name[prefix_len:] for blob in blobs]
        except Exception as e:
            logger.error(f"Failed to list files in Azure: {e}")
            return []

    def get_size(self, remote_path: str) -> int:
        """Get file size from Azure."""
        try:
            blob_name = self._get_blob_name(remote_path)
            blob_client = self.container_client.get_blob_client(blob_name)
            properties = blob_client.get_blob_properties()
            return properties.size
        except Exception as e:
            logger.error(f"Failed to get size of {remote_path} from Azure: {e}")
            return 0

    def get_metadata(self, remote_path: str) -> dict:
        """Get file metadata from Azure."""
        try:
            blob_name = self._get_blob_name(remote_path)
            blob_client = self.container_client.get_blob_client(blob_name)
            properties = blob_client.get_blob_properties()
            return {
                'size': properties.size,
                'created': properties.creation_time,
                'modified': properties.last_modified,
                'content_type': properties.content_settings.content_type,
                'blob_type': properties.blob_type
            }
        except Exception as e:
            logger.error(f"Failed to get metadata for {remote_path} from Azure: {e}")
            return {}

