"""
Tests for cache module.
"""

import unittest
import time
from unittest.mock import Mock, MagicMock, patch

from bountybot.cache import (
    RedisClient,
    RedisConfig,
    RedisMode,
    CacheManager,
    CacheStrategy,
    DistributedRateLimiter,
    CacheWarmer,
    JSONSerializer,
    MessagePackSerializer,
    PickleSerializer
)


class TestSerializers(unittest.TestCase):
    """Test serializers."""
    
    def test_json_serializer(self):
        """Test JSON serializer."""
        serializer = JSONSerializer()
        
        data = {'key': 'value', 'number': 42, 'list': [1, 2, 3]}
        serialized = serializer.serialize(data)
        deserialized = serializer.deserialize(serialized)
        
        self.assertEqual(data, deserialized)
    
    def test_json_serializer_with_compression(self):
        """Test JSON serializer with compression."""
        serializer = JSONSerializer(compress=True)
        
        data = {'key': 'value' * 100}  # Compressible data
        serialized = serializer.serialize(data)
        deserialized = serializer.deserialize(serialized)
        
        self.assertEqual(data, deserialized)
    
    def test_pickle_serializer(self):
        """Test Pickle serializer."""
        serializer = PickleSerializer()
        
        # Test with Python objects
        data = {'key': 'value', 'set': {1, 2, 3}, 'tuple': (1, 2, 3)}
        serialized = serializer.serialize(data)
        deserialized = serializer.deserialize(serialized)
        
        self.assertEqual(data, deserialized)


class TestRedisConfig(unittest.TestCase):
    """Test Redis configuration."""
    
    def test_default_config(self):
        """Test default configuration."""
        config = RedisConfig()
        
        self.assertEqual(config.host, 'localhost')
        self.assertEqual(config.port, 6379)
        self.assertEqual(config.db, 0)
        self.assertEqual(config.mode, RedisMode.STANDALONE)
    
    @patch.dict('os.environ', {
        'REDIS_HOST': 'redis.example.com',
        'REDIS_PORT': '6380',
        'REDIS_DB': '1',
        'REDIS_PASSWORD': 'secret'
    })
    def test_from_env(self):
        """Test configuration from environment."""
        config = RedisConfig.from_env()
        
        self.assertEqual(config.host, 'redis.example.com')
        self.assertEqual(config.port, 6380)
        self.assertEqual(config.db, 1)
        self.assertEqual(config.password, 'secret')


class TestRedisClient(unittest.TestCase):
    """Test Redis client."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.config = RedisConfig()
        self.client = RedisClient(self.config)
    
    def test_initialization(self):
        """Test client initialization."""
        self.assertIsNotNone(self.client)
        self.assertEqual(self.client.config, self.config)
        self.assertFalse(self.client._connected)
    
    def test_connect_without_redis(self):
        """Test connection without redis package."""
        client = RedisClient()
        client.redis = None
        
        result = client.connect()
        self.assertFalse(result)
    
    def test_is_connected(self):
        """Test connection check."""
        self.assertFalse(self.client.is_connected())
    
    def test_get_info_not_connected(self):
        """Test get_info when not connected."""
        info = self.client.get_info()
        self.assertEqual(info, {})
    
    def test_get_stats_not_connected(self):
        """Test get_stats when not connected."""
        stats = self.client.get_stats()
        self.assertFalse(stats['connected'])


class TestCacheManager(unittest.TestCase):
    """Test cache manager."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Mock Redis client
        self.mock_redis_client = Mock(spec=RedisClient)
        self.mock_redis_client.is_connected.return_value = False
        self.mock_redis_client.connect.return_value = True
        
        self.cache_manager = CacheManager(
            redis_client=self.mock_redis_client,
            namespace='test'
        )
    
    def test_initialization(self):
        """Test cache manager initialization."""
        self.assertIsNotNone(self.cache_manager)
        self.assertEqual(self.cache_manager.namespace, 'test')
        self.assertEqual(self.cache_manager.default_ttl, 3600)
    
    def test_make_key(self):
        """Test key generation."""
        key = self.cache_manager._make_key('mykey')
        self.assertEqual(key, 'test:mykey')
        
        key_with_version = self.cache_manager._make_key('mykey', version='v1')
        self.assertEqual(key_with_version, 'test:vv1:mykey')
    
    def test_hash_key(self):
        """Test key hashing."""
        hash1 = self.cache_manager._hash_key('test_data')
        hash2 = self.cache_manager._hash_key('test_data')
        hash3 = self.cache_manager._hash_key('different_data')
        
        self.assertEqual(hash1, hash2)
        self.assertNotEqual(hash1, hash3)
        self.assertEqual(len(hash1), 16)
    
    def test_get_without_redis(self):
        """Test get without Redis connection."""
        self.mock_redis_client.get_client.return_value = None
        
        value = self.cache_manager.get('key')
        self.assertIsNone(value)
        self.assertEqual(self.cache_manager.misses, 1)
    
    def test_set_without_redis(self):
        """Test set without Redis connection."""
        self.mock_redis_client.get_client.return_value = None
        
        result = self.cache_manager.set('key', 'value')
        self.assertFalse(result)
    
    def test_get_stats(self):
        """Test statistics."""
        stats = self.cache_manager.get_stats()
        
        self.assertIn('hits', stats)
        self.assertIn('misses', stats)
        self.assertIn('sets', stats)
        self.assertIn('deletes', stats)
        self.assertIn('hit_rate_percent', stats)
        self.assertIn('namespace', stats)
    
    def test_reset_stats(self):
        """Test statistics reset."""
        self.cache_manager.hits = 10
        self.cache_manager.misses = 5
        
        self.cache_manager.reset_stats()
        
        self.assertEqual(self.cache_manager.hits, 0)
        self.assertEqual(self.cache_manager.misses, 0)


class TestDistributedRateLimiter(unittest.TestCase):
    """Test distributed rate limiter."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Mock Redis client
        self.mock_redis_client = Mock(spec=RedisClient)
        self.mock_redis_client.is_connected.return_value = False
        self.mock_redis_client.connect.return_value = True
        
        self.rate_limiter = DistributedRateLimiter(
            redis_client=self.mock_redis_client,
            namespace='ratelimit'
        )
    
    def test_initialization(self):
        """Test rate limiter initialization."""
        self.assertIsNotNone(self.rate_limiter)
        self.assertEqual(self.rate_limiter.namespace, 'ratelimit')
    
    def test_make_key(self):
        """Test key generation."""
        key = self.rate_limiter._make_key('user123', 'api')
        self.assertEqual(key, 'ratelimit:api:user123')
    
    def test_check_rate_limit_without_redis(self):
        """Test rate limit check without Redis."""
        self.mock_redis_client.get_client.return_value = None
        
        allowed, info = self.rate_limiter.check_rate_limit_token_bucket(
            'user123', 100, 10.0
        )
        
        # Should fail open
        self.assertTrue(allowed)
        self.assertIn('error', info)
    
    def test_reset_rate_limit_without_redis(self):
        """Test rate limit reset without Redis."""
        self.mock_redis_client.get_client.return_value = None
        
        result = self.rate_limiter.reset_rate_limit('user123')
        self.assertFalse(result)


class TestCacheWarmer(unittest.TestCase):
    """Test cache warmer."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Mock cache manager
        self.mock_cache_manager = Mock(spec=CacheManager)
        self.cache_warmer = CacheWarmer(self.mock_cache_manager)
    
    def test_initialization(self):
        """Test cache warmer initialization."""
        self.assertIsNotNone(self.cache_warmer)
        self.assertFalse(self.cache_warmer._running)
        self.assertEqual(len(self.cache_warmer._warmers), 0)
    
    def test_register_warmer(self):
        """Test warmer registration."""
        def factory():
            return {'key1': 'value1', 'key2': 'value2'}
        
        self.cache_warmer.register_warmer(
            name='test_warmer',
            factory=factory,
            interval_seconds=60
        )
        
        self.assertEqual(len(self.cache_warmer._warmers), 1)
        self.assertEqual(self.cache_warmer._warmers[0]['name'], 'test_warmer')
    
    def test_unregister_warmer(self):
        """Test warmer unregistration."""
        def factory():
            return {}
        
        self.cache_warmer.register_warmer('test_warmer', factory)
        self.assertEqual(len(self.cache_warmer._warmers), 1)
        
        self.cache_warmer.unregister_warmer('test_warmer')
        self.assertEqual(len(self.cache_warmer._warmers), 0)
    
    def test_enable_disable_warmer(self):
        """Test enabling/disabling warmer."""
        def factory():
            return {}
        
        self.cache_warmer.register_warmer('test_warmer', factory, enabled=False)
        self.assertFalse(self.cache_warmer._warmers[0]['enabled'])
        
        self.cache_warmer.enable_warmer('test_warmer')
        self.assertTrue(self.cache_warmer._warmers[0]['enabled'])
        
        self.cache_warmer.disable_warmer('test_warmer')
        self.assertFalse(self.cache_warmer._warmers[0]['enabled'])
    
    def test_warm_now(self):
        """Test immediate warming."""
        def factory():
            return {'key1': 'value1', 'key2': 'value2'}
        
        self.cache_warmer.register_warmer('test_warmer', factory)
        results = self.cache_warmer.warm_now('test_warmer')
        
        self.assertIn('test_warmer', results)
        self.assertTrue(results['test_warmer']['success'])
        self.assertEqual(results['test_warmer']['keys_cached'], 2)
    
    def test_get_status(self):
        """Test status retrieval."""
        def factory():
            return {}
        
        self.cache_warmer.register_warmer('test_warmer', factory)
        status = self.cache_warmer.get_status()
        
        self.assertFalse(status['running'])
        self.assertEqual(status['total_warmers'], 1)
        self.assertEqual(status['enabled_warmers'], 1)
        self.assertEqual(len(status['warmers']), 1)
    
    def test_get_stats(self):
        """Test statistics retrieval."""
        stats = self.cache_warmer.get_stats()
        
        self.assertIn('running', stats)
        self.assertIn('total_warmers', stats)
        self.assertIn('total_runs', stats)
        self.assertIn('success_rate_percent', stats)


if __name__ == '__main__':
    unittest.main()

