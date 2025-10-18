"""
Serializers for cache data.
"""

import json
import pickle
import logging
import zlib
from abc import ABC, abstractmethod
from typing import Any, Optional

logger = logging.getLogger(__name__)


class Serializer(ABC):
    """Abstract base class for serializers."""
    
    def __init__(self, compress: bool = False, compression_level: int = 6):
        """
        Initialize serializer.
        
        Args:
            compress: Whether to compress data
            compression_level: Compression level (1-9, higher = more compression)
        """
        self.compress = compress
        self.compression_level = compression_level
    
    @abstractmethod
    def serialize(self, data: Any) -> bytes:
        """
        Serialize data to bytes.
        
        Args:
            data: Data to serialize
            
        Returns:
            Serialized bytes
        """
        pass
    
    @abstractmethod
    def deserialize(self, data: bytes) -> Any:
        """
        Deserialize bytes to data.
        
        Args:
            data: Bytes to deserialize
            
        Returns:
            Deserialized data
        """
        pass
    
    def _compress(self, data: bytes) -> bytes:
        """Compress data using zlib."""
        if not self.compress:
            return data
        return zlib.compress(data, level=self.compression_level)
    
    def _decompress(self, data: bytes) -> bytes:
        """Decompress data using zlib."""
        if not self.compress:
            return data
        return zlib.decompress(data)


class JSONSerializer(Serializer):
    """JSON serializer."""
    
    def serialize(self, data: Any) -> bytes:
        """Serialize data to JSON bytes."""
        try:
            json_str = json.dumps(data, default=str)
            json_bytes = json_str.encode('utf-8')
            return self._compress(json_bytes)
        except Exception as e:
            logger.error(f"JSON serialization failed: {e}")
            raise
    
    def deserialize(self, data: bytes) -> Any:
        """Deserialize JSON bytes to data."""
        try:
            decompressed = self._decompress(data)
            json_str = decompressed.decode('utf-8')
            return json.loads(json_str)
        except Exception as e:
            logger.error(f"JSON deserialization failed: {e}")
            raise


class MessagePackSerializer(Serializer):
    """MessagePack serializer (more efficient than JSON)."""
    
    def __init__(self, compress: bool = False, compression_level: int = 6):
        """Initialize MessagePack serializer."""
        super().__init__(compress, compression_level)
        
        try:
            import msgpack
            self.msgpack = msgpack
        except ImportError:
            logger.warning("msgpack not installed. Install with: pip install msgpack")
            self.msgpack = None
    
    def serialize(self, data: Any) -> bytes:
        """Serialize data to MessagePack bytes."""
        if not self.msgpack:
            raise RuntimeError("msgpack not available")
        
        try:
            msgpack_bytes = self.msgpack.packb(data, use_bin_type=True)
            return self._compress(msgpack_bytes)
        except Exception as e:
            logger.error(f"MessagePack serialization failed: {e}")
            raise
    
    def deserialize(self, data: bytes) -> Any:
        """Deserialize MessagePack bytes to data."""
        if not self.msgpack:
            raise RuntimeError("msgpack not available")
        
        try:
            decompressed = self._decompress(data)
            return self.msgpack.unpackb(decompressed, raw=False)
        except Exception as e:
            logger.error(f"MessagePack deserialization failed: {e}")
            raise


class PickleSerializer(Serializer):
    """
    Pickle serializer (supports Python objects).
    
    WARNING: Only use with trusted data. Pickle can execute arbitrary code.
    """
    
    def __init__(self, compress: bool = False, compression_level: int = 6, protocol: int = pickle.HIGHEST_PROTOCOL):
        """
        Initialize Pickle serializer.
        
        Args:
            compress: Whether to compress data
            compression_level: Compression level
            protocol: Pickle protocol version
        """
        super().__init__(compress, compression_level)
        self.protocol = protocol
    
    def serialize(self, data: Any) -> bytes:
        """Serialize data to Pickle bytes."""
        try:
            pickle_bytes = pickle.dumps(data, protocol=self.protocol)
            return self._compress(pickle_bytes)
        except Exception as e:
            logger.error(f"Pickle serialization failed: {e}")
            raise
    
    def deserialize(self, data: bytes) -> Any:
        """Deserialize Pickle bytes to data."""
        try:
            decompressed = self._decompress(data)
            return pickle.loads(decompressed)
        except Exception as e:
            logger.error(f"Pickle deserialization failed: {e}")
            raise


def get_serializer(
    serializer_type: str = 'json',
    compress: bool = False,
    compression_level: int = 6
) -> Serializer:
    """
    Get serializer by type.
    
    Args:
        serializer_type: Serializer type ('json', 'msgpack', 'pickle')
        compress: Whether to compress data
        compression_level: Compression level (1-9)
        
    Returns:
        Serializer instance
    """
    serializers = {
        'json': JSONSerializer,
        'msgpack': MessagePackSerializer,
        'pickle': PickleSerializer
    }
    
    serializer_class = serializers.get(serializer_type.lower())
    if not serializer_class:
        raise ValueError(f"Unknown serializer type: {serializer_type}")
    
    return serializer_class(compress=compress, compression_level=compression_level)


# Convenience functions
def serialize_json(data: Any, compress: bool = False) -> bytes:
    """Serialize data to JSON bytes."""
    serializer = JSONSerializer(compress=compress)
    return serializer.serialize(data)


def deserialize_json(data: bytes, compress: bool = False) -> Any:
    """Deserialize JSON bytes to data."""
    serializer = JSONSerializer(compress=compress)
    return serializer.deserialize(data)


def serialize_msgpack(data: Any, compress: bool = False) -> bytes:
    """Serialize data to MessagePack bytes."""
    serializer = MessagePackSerializer(compress=compress)
    return serializer.serialize(data)


def deserialize_msgpack(data: bytes, compress: bool = False) -> Any:
    """Deserialize MessagePack bytes to data."""
    serializer = MessagePackSerializer(compress=compress)
    return serializer.deserialize(data)


def serialize_pickle(data: Any, compress: bool = False) -> bytes:
    """Serialize data to Pickle bytes."""
    serializer = PickleSerializer(compress=compress)
    return serializer.serialize(data)


def deserialize_pickle(data: bytes, compress: bool = False) -> Any:
    """Deserialize Pickle bytes to data."""
    serializer = PickleSerializer(compress=compress)
    return serializer.deserialize(data)

