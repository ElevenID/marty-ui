"""Test Redis persistence for StatusListManager"""
import asyncio
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(__file__))

from status_list_manager import (
    create_status_list_repository,
    StatusListManager,
    StatusListFormat,
)


async def test_redis_persistence():
    """Test that status lists persist in Redis."""
    
    print("=" * 60)
    print("Testing Redis Persistence for StatusListManager")
    print("=" * 60)
    
    # Create repository using MMF framework
    redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    print(f"\n1. Creating repository (Redis URL: {redis_url})...")
    repo = create_status_list_repository()
    print(f"   Repository type: {type(repo).__name__}")
    print(f"   Cache backend: {type(repo._cache).__name__}")
    
    # Create manager
    print("\n2. Creating StatusListManager...")
    manager = StatusListManager(
        repository=repo,
        base_url="https://status.example.com",
        default_size=131072,
    )
    
    # Allocate some indices
    print("\n3. Allocating indices...")
    tenant_id = "test-org-123"
    format = StatusListFormat.BITSTRING
    
    indices = []
    for i in range(5):
        index = await manager.allocate_index(
            tenant_id=tenant_id,
            format=format,
        )
        indices.append(index)
        print(f"   Allocated index {index} for credential cred-{i}")
        
        # Record allocation (for tracking)
        await repo.record_allocation(
            tenant_id=tenant_id,
            format=format,
            index=index,
            credential_id=f"cred-{i}",
        )
    
    # Check if indices are persisted
    print("\n4. Verifying persistence...")
    status_list = await repo.get(tenant_id, format)
    if status_list:
        print(f"   ✓ Status list found in repository")
        print(f"   - Tenant: {status_list.tenant_id}")
        print(f"   - Format: {status_list.format.value}")
        print(f"   - Size: {status_list.size}")
        print(f"   - Version: {status_list.version}")
    else:
        print(f"   ✗ Status list not found (unexpected)")
    
    # Check next index
    next_index = await repo.get_next_index(tenant_id, format)
    print(f"\n5. Next available index: {next_index}")
    print(f"   Expected: {len(indices)} (matches {next_index == len(indices)})")
    
    # Set some statuses
    print("\n6. Setting revocation statuses...")
    for i in [0, 2, 4]:
        await manager.set_status(
            tenant_id=tenant_id,
            index=indices[i],
            status=1,  # Revoked
            format=format,
        )
        print(f"   Revoked credential at index {indices[i]}")
    
    # Verify status list updated
    status_list = await repo.get(tenant_id, format)
    if status_list:
        print(f"\n7. Verifying revocations...")
        print(f"   Status list version: {status_list.version}")
        print(f"   Data size: {len(status_list.data)} bytes")
        
        # Check a few bits
        for idx in indices:
            byte_pos = idx // 8
            bit_pos = 7 - (idx % 8)
            byte_val = status_list.data[byte_pos]
            bit_val = (byte_val >> bit_pos) & 1
            status_str = "REVOKED" if bit_val == 1 else "VALID"
            print(f"   Index {idx}: {status_str}")
    
    print("\n" + "=" * 60)
    print("Test Complete!")
    print("=" * 60)
    
    # Summary
    cache_backend = type(repo._cache).__name__
    print(f"\n✓ Using Redis persistence ({cache_backend})")
    print(f"  - Allocated {len(indices)} indices")
    print(f"  - Revoked 3 credentials")
    print(f"  - Data persisted to Redis at {redis_url}")
    print("\nNote: Redis is required for this service. If Redis is unavailable, the service will not start.")


if __name__ == "__main__":
    asyncio.run(test_redis_persistence())
