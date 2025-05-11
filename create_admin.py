from app import app, db
from models import User
import sys

def create_admin_user():
    with app.app_context():
        # Default admin credentials
        username = "admin"
        email = "mmnjenga2@gmail.com"
        password = "Password@123"  # Default password, should be changed after first login
        
        # Check if admin user already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            print(f"Error: Admin user already exists!")
            sys.exit(1)
            
        # Create admin user
        admin = User(
            username=username,
            email=email,
            role='admin',
            is_active=True
        )
        admin.set_password(password)
        
        # Add to database
        db.session.add(admin)
        db.session.commit()
        
        print(f"Admin user created successfully!")
        print(f"Username: {username}")
        print(f"Password: {password}")
        print("Please change the password after first login!")

if __name__ == '__main__':
    create_admin_user() 