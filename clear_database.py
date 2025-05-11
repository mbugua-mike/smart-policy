from app import app, db
import sys

def clear_database():
    with app.app_context():
        # Drop all tables
        print("Dropping all tables...")
        db.drop_all()
        
        # Create all tables
        print("Creating all tables...")
        db.create_all()
        
        print("Database cleared and recreated successfully!")

if __name__ == '__main__':
    # Ask for confirmation
    confirm = input("WARNING: This will delete ALL data in the database. Are you sure? (yes/no): ")
    if confirm.lower() == 'yes':
        clear_database()
    else:
        print("Operation cancelled.")
        sys.exit(0) 