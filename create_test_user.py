from app import app, User, db
import bcrypt

def create_test_user():
    with app.app_context():
        # Check if test user exists
        if not User.query.filter_by(username='test_user').first():
            # Create test user
            hashed_password = bcrypt.hashpw('Test123!'.encode('utf-8'), bcrypt.gensalt())
            test_user = User(
                username='test_user',
                email='test@example.com',
                password_hash=hashed_password,
                role='user',
                is_active=True
            )
            db.session.add(test_user)
            db.session.commit()
            print("Test user created successfully")
        else:
            print("Test user already exists")

if __name__ == '__main__':
    create_test_user()
