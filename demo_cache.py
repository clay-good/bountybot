"""
Demo: Redis Caching & Performance Optimization

Demonstrates the distributed caching capabilities of BountyBot.
"""

import time
from datetime import datetime

from bountybot.cache import (
    RedisClient,
    RedisConfig,
    CacheManager,
    CacheStrategy,
    DistributedRateLimiter,
    CacheWarmer,
    JSONSerializer,
    PickleSerializer
)


def print_section(title: str):
    """Print a section header."""
    print(f"\n{'=' * 80}")
    print(f"  {title}")
    print(f"{'=' * 80}\n")


def demo_redis_client():
    """Demonstrate Redis client."""
    print_section("1. Redis Client & Connection Management")
    
    # Create Redis configuration
    config = RedisConfig(
        host='localhost',
        port=6379,
        db=0,
        max_connections=50
    )
    
    print(f"📝 Redis Configuration:")
    print(f"  - Host: {config.host}")
    print(f"  - Port: {config.port}")
    print(f"  - Database: {config.db}")
    print(f"  - Max Connections: {config.max_connections}")
    print(f"  - Mode: {config.mode.value}")
    
    # Create Redis client
    redis_client = RedisClient(config)
    
    print(f"\n✓ Redis client created")
    
    # Try to connect
    print(f"\n🔌 Attempting to connect to Redis...")
    connected = redis_client.connect()
    
    if connected:
        print(f"✓ Connected to Redis successfully!")
        
        # Get Redis info
        info = redis_client.get_info()
        print(f"\n📊 Redis Server Info:")
        print(f"  - Version: {info.get('redis_version', 'N/A')}")
        print(f"  - Memory Used: {info.get('used_memory_human', 'N/A')}")
        print(f"  - Connected Clients: {info.get('connected_clients', 'N/A')}")
        print(f"  - Uptime: {info.get('uptime_in_seconds', 'N/A')} seconds")
        
        # Health check
        print(f"\n🏥 Running health check...")
        healthy = redis_client.health_check()
        print(f"  - Health Status: {'✓ Healthy' if healthy else '✗ Unhealthy'}")
        
        redis_client.disconnect()
    else:
        print(f"⚠️  Could not connect to Redis (this is expected if Redis is not running)")
        print(f"   Install Redis: brew install redis (macOS) or apt-get install redis (Linux)")
        print(f"   Start Redis: redis-server")
        print(f"\n💡 Demo will continue with mock operations...")


def demo_cache_manager():
    """Demonstrate cache manager."""
    print_section("2. Cache Manager & Caching Strategies")
    
    # Create cache manager
    cache_manager = CacheManager(
        namespace='bountybot',
        default_ttl=3600,
        strategy=CacheStrategy.CACHE_ASIDE
    )
    
    print(f"✓ Cache manager created")
    print(f"  - Namespace: {cache_manager.namespace}")
    print(f"  - Default TTL: {cache_manager.default_ttl} seconds")
    print(f"  - Strategy: {cache_manager.strategy.value}")
    
    # Demonstrate cache operations (will work even without Redis)
    print(f"\n📦 Cache Operations:")
    
    # Set value
    print(f"\n1. SET operation:")
    print(f"   cache.set('user:123', {{'name': 'John', 'role': 'admin'}})")
    success = cache_manager.set('user:123', {'name': 'John', 'role': 'admin'}, ttl=300)
    print(f"   Result: {'✓ Success' if success else '✗ Failed (Redis not available)'}")
    
    # Get value
    print(f"\n2. GET operation:")
    print(f"   cache.get('user:123')")
    value = cache_manager.get('user:123')
    print(f"   Result: {value if value else '✗ Not found (Redis not available)'}")
    
    # Get or set
    print(f"\n3. GET_OR_SET operation:")
    print(f"   cache.get_or_set('expensive_query', lambda: compute_expensive_result())")
    
    def compute_expensive_result():
        print(f"   Computing expensive result...")
        time.sleep(0.1)
        return {'result': 'computed_value', 'timestamp': datetime.now().isoformat()}
    
    result = cache_manager.get_or_set('expensive_query', compute_expensive_result, ttl=600)
    print(f"   Result: {result if result else '✗ Failed'}")
    
    # Batch operations
    print(f"\n4. BATCH operations:")
    print(f"   cache.set_many({{'key1': 'val1', 'key2': 'val2', 'key3': 'val3'}})")
    success = cache_manager.set_many({
        'key1': 'value1',
        'key2': 'value2',
        'key3': 'value3'
    }, ttl=300)
    print(f"   Result: {'✓ Success' if success else '✗ Failed'}")
    
    print(f"\n   cache.get_many(['key1', 'key2', 'key3'])")
    values = cache_manager.get_many(['key1', 'key2', 'key3'])
    print(f"   Result: {values if values else '✗ Not found'}")
    
    # Statistics
    print(f"\n📊 Cache Statistics:")
    stats = cache_manager.get_stats()
    print(f"  - Hits: {stats['hits']}")
    print(f"  - Misses: {stats['misses']}")
    print(f"  - Sets: {stats['sets']}")
    print(f"  - Hit Rate: {stats['hit_rate_percent']}%")
    print(f"  - Total Requests: {stats['total_requests']}")


def demo_rate_limiter():
    """Demonstrate distributed rate limiter."""
    print_section("3. Distributed Rate Limiting")
    
    # Create rate limiter
    rate_limiter = DistributedRateLimiter(namespace='ratelimit')
    
    print(f"✓ Distributed rate limiter created")
    
    # Token bucket algorithm
    print(f"\n🪣 Token Bucket Algorithm:")
    print(f"   - Max tokens: 100")
    print(f"   - Refill rate: 10 tokens/second")
    print(f"   - Tokens requested: 5")
    
    for i in range(5):
        allowed, info = rate_limiter.check_rate_limit_token_bucket(
            identifier='user123',
            max_tokens=100,
            refill_rate=10.0,
            tokens_requested=5,
            resource='api'
        )
        
        if 'error' not in info:
            status = '✓ Allowed' if allowed else '✗ Blocked'
            remaining = info.get('remaining_tokens', 0)
            print(f"   Request {i+1}: {status} (Remaining: {remaining:.1f} tokens)")
        else:
            print(f"   Request {i+1}: ⚠️  Redis not available")
            break
        
        time.sleep(0.1)
    
    # Fixed window algorithm
    print(f"\n🪟 Fixed Window Algorithm:")
    print(f"   - Max requests: 10 per 60 seconds")
    
    for i in range(3):
        allowed, info = rate_limiter.check_rate_limit_fixed_window(
            identifier='user456',
            max_requests=10,
            window_seconds=60,
            resource='api'
        )
        
        if 'error' not in info:
            status = '✓ Allowed' if allowed else '✗ Blocked'
            count = info.get('current_count', 0)
            print(f"   Request {i+1}: {status} (Count: {count}/10)")
        else:
            print(f"   Request {i+1}: ⚠️  Redis not available")
            break
    
    # Sliding window algorithm
    print(f"\n📊 Sliding Window Algorithm:")
    print(f"   - Max requests: 5 per 10 seconds")
    
    for i in range(3):
        allowed, info = rate_limiter.check_rate_limit_sliding_window(
            identifier='user789',
            max_requests=5,
            window_seconds=10,
            resource='api'
        )
        
        if 'error' not in info:
            status = '✓ Allowed' if allowed else '✗ Blocked'
            count = info.get('current_count', 0)
            print(f"   Request {i+1}: {status} (Count: {count}/5)")
        else:
            print(f"   Request {i+1}: ⚠️  Redis not available")
            break


def demo_cache_warmer():
    """Demonstrate cache warmer."""
    print_section("4. Cache Warming & Preloading")
    
    # Create cache manager and warmer
    cache_manager = CacheManager(namespace='bountybot')
    cache_warmer = CacheWarmer(cache_manager)
    
    print(f"✓ Cache warmer created")
    
    # Register warmers
    print(f"\n📝 Registering cache warmers:")
    
    def warm_user_data():
        """Warm user data cache."""
        return {
            'user:1': {'name': 'Alice', 'role': 'admin'},
            'user:2': {'name': 'Bob', 'role': 'user'},
            'user:3': {'name': 'Charlie', 'role': 'user'}
        }
    
    def warm_config_data():
        """Warm configuration cache."""
        return {
            'config:max_reports': 1000,
            'config:timeout': 30,
            'config:retry_count': 3
        }
    
    cache_warmer.register_warmer(
        name='user_data',
        factory=warm_user_data,
        interval_seconds=300,
        priority=10
    )
    
    cache_warmer.register_warmer(
        name='config_data',
        factory=warm_config_data,
        interval_seconds=600,
        priority=5
    )
    
    print(f"  ✓ Registered 'user_data' warmer (every 5 minutes, priority 10)")
    print(f"  ✓ Registered 'config_data' warmer (every 10 minutes, priority 5)")
    
    # Run warmers immediately
    print(f"\n🔥 Running cache warmers:")
    results = cache_warmer.warm_now()
    
    for name, result in results.items():
        if result['success']:
            print(f"  ✓ {name}: {result['keys_cached']} keys cached in {result['duration_seconds']:.3f}s")
        else:
            print(f"  ✗ {name}: Failed - {result.get('error', 'Unknown error')}")
    
    # Get status
    print(f"\n📊 Cache Warmer Status:")
    status = cache_warmer.get_status()
    print(f"  - Running: {status['running']}")
    print(f"  - Total Warmers: {status['total_warmers']}")
    print(f"  - Enabled Warmers: {status['enabled_warmers']}")
    
    # Get statistics
    stats = cache_warmer.get_stats()
    print(f"\n📈 Cache Warmer Statistics:")
    print(f"  - Total Runs: {stats['total_runs']}")
    print(f"  - Successes: {stats['total_successes']}")
    print(f"  - Errors: {stats['total_errors']}")
    print(f"  - Success Rate: {stats['success_rate_percent']}%")


def demo_serializers():
    """Demonstrate serializers."""
    print_section("5. Serialization & Compression")
    
    test_data = {
        'report_id': '12345',
        'title': 'SQL Injection Vulnerability',
        'severity': 'CRITICAL',
        'cvss_score': 9.8,
        'tags': ['sql', 'injection', 'database'],
        'metadata': {
            'researcher': 'security_expert',
            'timestamp': datetime.now().isoformat()
        }
    }
    
    print(f"📦 Test Data:")
    print(f"  {test_data}")
    
    # JSON serializer
    print(f"\n1. JSON Serializer:")
    json_serializer = JSONSerializer(compress=False)
    json_data = json_serializer.serialize(test_data)
    print(f"   - Size: {len(json_data)} bytes")
    print(f"   - Deserialized: {json_serializer.deserialize(json_data)['title']}")
    
    # JSON with compression
    print(f"\n2. JSON Serializer (with compression):")
    json_compressed = JSONSerializer(compress=True, compression_level=9)
    json_comp_data = json_compressed.serialize(test_data)
    print(f"   - Size: {len(json_comp_data)} bytes")
    print(f"   - Compression Ratio: {len(json_data) / len(json_comp_data):.2f}x")
    
    # Pickle serializer
    print(f"\n3. Pickle Serializer:")
    pickle_serializer = PickleSerializer(compress=False)
    pickle_data = pickle_serializer.serialize(test_data)
    print(f"   - Size: {len(pickle_data)} bytes")
    print(f"   - Deserialized: {pickle_serializer.deserialize(pickle_data)['title']}")


def main():
    """Run all demos."""
    print("\n" + "=" * 80)
    print("  BountyBot - Redis Caching & Performance Optimization Demo")
    print("=" * 80)
    
    try:
        demo_redis_client()
        demo_cache_manager()
        demo_rate_limiter()
        demo_cache_warmer()
        demo_serializers()
        
        print_section("Demo Complete!")
        print("✅ All caching and performance optimization features demonstrated!")
        print("\n📚 Key Features:")
        print("  ✓ Redis connection management with pooling")
        print("  ✓ Distributed caching (cross-instance)")
        print("  ✓ Multiple caching strategies (cache-aside, write-through, etc.)")
        print("  ✓ Distributed rate limiting (token bucket, fixed/sliding window)")
        print("  ✓ Cache warming and preloading")
        print("  ✓ Multiple serializers (JSON, MessagePack, Pickle)")
        print("  ✓ Compression support (zlib)")
        print("  ✓ Cache analytics and monitoring")
        print("  ✓ High availability (Sentinel) and scaling (Cluster) support")
        
    except Exception as e:
        print(f"\n❌ Demo failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()

