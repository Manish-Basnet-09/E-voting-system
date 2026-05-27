import asyncio
import sys
import os

# 🌟 Add the parent directory (backend) to the path so we can import 'app'
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.config import settings
from sqlalchemy.ext.asyncio import create_async_engine

async def test_connection():
    print("⏳ Attempting to connect to database using:", settings.database_url)
    engine = create_async_engine(settings.database_url, echo=True)
    try:
        async with engine.connect() as conn:
            print("✅ SUCCESS: Successfully connected to the database!")
        await engine.dispose()
    except Exception as e:
        print(f"❌ FAILED: Could not connect to the database.")
        print(f"Error details: {e}")

if __name__ == "__main__":
    asyncio.run(test_connection())