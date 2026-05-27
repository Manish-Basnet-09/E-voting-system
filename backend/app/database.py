from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base
from .config import settings

# 1. Create the Async Engine (Optimized for asynchronous PostgreSQL)
# We drop check_same_thread because Postgres handles multi-threading natively
engine = create_async_engine(
    settings.database_url,
    echo=False,
    pool_size=10,
    max_overflow=20
)

# 2. Create the Async Session Factory
AsyncSessionLocal = async_sessionmaker(
    autocommit=False, 
    autoflush=False, 
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False
)

# 3. Maintain your declarative base layer
Base = declarative_base()


# 4. Asynchronous Database Session Dependency for your API routers
async def get_db():
    async with AsyncSessionLocal() as db:
        try:
            yield db
        finally:
            await db.close()


# 5. Asynchronous Table Creation Tool
async def create_tables():
    # Keep your exact conditional models import intact
    from .models import user, election, candidate, vote  # noqa: F401
    
    # Bridge the async connection to create tables synchronously via metadata
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)