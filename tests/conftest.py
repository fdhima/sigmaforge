import os
import asyncio
import pytest
import pytest_asyncio
from dotenv import load_dotenv
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.pool import NullPool

from app.main import app
from app.database import Base, get_session
from app.core.security import create_access_token, hash_password
from app.models.user import User

load_dotenv()

TEST_DATABASE_URL = os.getenv('TEST_DATABASE_URL')

engine = create_async_engine(TEST_DATABASE_URL, echo=False, poolclass=NullPool)
TestingSessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for each test case."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="session", autouse=True)
async def setup_database():
    """Create all tables once before the test session, drop after."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    # Create test user once for the whole session
    async with TestingSessionLocal() as session:
        user = User(username="testuser", hashed_password=hash_password("password"))
        session.add(user)
        await session.commit()
        
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture()
async def db():
    """Each test gets a session."""
    async with TestingSessionLocal() as session:
        yield session
        await session.rollback()


@pytest_asyncio.fixture()
async def client(db):
    """Override the app's session dependency with the test session."""
    async def override_get_session():
        yield db

    app.dependency_overrides[get_session] = override_get_session
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture()
def normal_user_token():
    """Generate a valid JWT for a test user."""
    return create_access_token(data={"sub": "testuser"})
