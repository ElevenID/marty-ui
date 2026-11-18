"""Run only inside the pinned legacy runtime on an isolated synthetic Postgres network."""

from __future__ import annotations

import asyncio
import os

from sqlalchemy import delete, select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.engine import make_url

from revocation_profile.main import RevocationProfile, RevocationProfileStatus
from revocation_profile.infrastructure.adapters.postgres_adapter import PostgresRevocationProfileRepository
from revocation_profile.infrastructure.models import mapper_registry, revocation_profiles_table as table


SYSTEM = "system"
DEFAULT = "Auto Revocation (Default)"
CANONICAL = "00000000-0000-0000-0000-000000000001"


async def run() -> None:
    dsn = os.environ.get("TEST_DATABASE_URL", "")
    if os.environ.get("D12_ISOLATED_TEST_ONLY") != "1":
        raise RuntimeError("ISOLATED_TEST_MARKER_REQUIRED")
    url = make_url(dsn)
    if (url.drivername != "postgresql+asyncpg" or url.host != "d12-revocation-compat-pg"
            or url.database != "d12_revocation_compat"):
        raise RuntimeError("ISOLATED_TEST_DATABASE_IDENTITY_REQUIRED")
    engine = create_async_engine(dsn, echo=False)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    repo = PostgresRevocationProfileRepository(factory)
    try:
        async with engine.begin() as conn:
            await conn.execute(text("CREATE SCHEMA revocation_profile_service"))
            await conn.run_sync(mapper_registry.metadata.create_all)

        for _ in range(39):
            await repo.save(RevocationProfile(organization_id=SYSTEM, name=DEFAULT,
                                              status=RevocationProfileStatus.ACTIVE))
        canonical = RevocationProfile(organization_id=CANONICAL, name=DEFAULT,
                                       status=RevocationProfileStatus.ACTIVE)
        await repo.save(canonical)
        unrelated = RevocationProfile(organization_id="other-test-org", name="Unrelated Profile")
        await repo.save(unrelated)

        async def rows(org: str):
            async with factory() as session:
                result = await session.execute(
                    select(table).where(table.c.organization_id == org).order_by(table.c.id)
                )
                return [dict(row._mapping) for row in result.all()]

        before = await rows(SYSTEM)
        assert len(before) == 39 and len({row["id"] for row in before}) == 39
        results = await asyncio.gather(*(repo.ensure_system_default(
            RevocationProfile(organization_id=SYSTEM, name=DEFAULT)) for _ in range(8)))
        assert results == [False] * 8
        assert await rows(SYSTEM) == before
        assert [row["id"] for row in await rows(CANONICAL)] == [canonical.id]
        assert [row["id"] for row in await rows("other-test-org")] == [unrelated.id]

        async with factory() as session:
            await session.execute(delete(table).where(table.c.organization_id == SYSTEM))
            await session.commit()
        fresh_results = await asyncio.gather(*(repo.ensure_system_default(
            RevocationProfile(organization_id=SYSTEM, name=DEFAULT)) for _ in range(8)))
        assert sum(fresh_results) == 1 and len(await rows(SYSTEM)) == 1

        async with factory() as session:
            await session.execute(delete(table).where(table.c.organization_id == SYSTEM))
            await session.commit()
        original_serializer = repo._profile_row_data
        repo._profile_row_data = lambda _: (_ for _ in ()).throw(RuntimeError("injected-before-insert"))
        try:
            try:
                await repo.ensure_system_default(RevocationProfile(organization_id=SYSTEM, name=DEFAULT))
            except RuntimeError as exc:
                assert str(exc) == "injected-before-insert"
            else:
                raise AssertionError("injected error did not abort")
        finally:
            repo._profile_row_data = original_serializer
        assert await rows(SYSTEM) == []
        assert await repo.ensure_system_default(RevocationProfile(organization_id=SYSTEM, name=DEFAULT))
        assert len(await rows(SYSTEM)) == 1

        fetched = await repo.get(unrelated.id)
        assert fetched is not None and fetched.organization_id == "other-test-org"
        unrelated.name = "Updated Unrelated Profile"
        await repo.save(unrelated)
        assert (await repo.get(unrelated.id)).name == unrelated.name
        assert len(await repo.list("other-test-org")) == 1
        await repo.delete(unrelated.id)
        assert await repo.get(unrelated.id) is None
        assert [row["id"] for row in await rows(CANONICAL)] == [canonical.id]
        print("ISOLATED_LEGACY_REVOCATION_PG_PASS")
    finally:
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(asyncio.wait_for(run(), timeout=90))
