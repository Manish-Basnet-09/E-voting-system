import asyncio
import bcrypt
from backend.app.database import AsyncSessionLocal
from backend.app.models.user import User

async def create_superuser():
    print(" 🚀 Re-Seeding Official Demo Admin Account...")
    
    # Matching the exact structural expectations of your frontend demo box
    admin_email = "admin@pmc.edu.np"
    admin_password = "Admin@123" 
    raw_student_id = "ADMIN001"                  
    
    # Generate cryptographic parameters
    salt_bytes = bcrypt.gensalt()
    salt_str = salt_bytes.decode('utf-8')
    
    password_hash = bcrypt.hashpw(admin_password.encode('utf-8'), salt_bytes).decode('utf-8')
    student_id_hash = bcrypt.hashpw(raw_student_id.encode('utf-8'), salt_bytes).decode('utf-8')
    
    # Standard static fallback or a standard TOTP base key string
    # We will use your working verified secret key string
    otp_secret_str = "FZ5HLFWUWUKNKV2L0"
    
    async with AsyncSessionLocal() as session:
        from sqlalchemy import select
        # Clean up any conflicting emails or records
        result = await session.execute(select(User).where(User.email == admin_email))
        existing_admin = result.scalar_one_or_none()
        
        if existing_admin:
            await session.delete(existing_admin)
            await session.commit()

        superuser = User(
            student_id_hash=student_id_hash,
            salt=salt_str,
            password_hash=password_hash,
            otp_secret=otp_secret_str,       
            full_name="System Administrator",
            email=admin_email,
            role="admin",
            is_active=True,
            has_voted=False
        )
        
        session.add(superuser)
        await session.commit()
        
        print("\n✅ System Admin fully synchronized with database!")
        print(f"   📧 Email: {admin_email}")
        print(f"   🔑 Student ID / Admin ID: {raw_student_id}")
        print(f"   🔒 Password: {admin_password}")
        print(f"   📱 2FA Setup Secret Key: {otp_secret_str}\n")

if __name__ == "__main__":
    asyncio.run(create_superuser())