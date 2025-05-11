from app import app, User, LoginAttempt, db, check_login_time_anomaly
from datetime import datetime, timedelta

def test_anomaly_detection():
    with app.app_context():
        # Get or create a test user
        test_user = User.query.filter_by(username='test_user').first()
        if not test_user:
            print("Please create a test user first")
            return

        # Clear previous login attempts
        LoginAttempt.query.filter_by(user_id=test_user.id).delete()
        db.session.commit()

        # Create some normal hour login history (9 AM - 5 PM UTC)
        normal_hours = [9, 10, 11, 14, 15, 16, 17]
        for hour in normal_hours:
            login = LoginAttempt(
                user_id=test_user.id,
                attempt_time=datetime.utcnow().replace(hour=hour),
                success=True,
                ip_address='127.0.0.1'
            )
            db.session.add(login)
        
        # Add a few unusual hour logins (1 AM UTC)
        unusual_hour = 1
        for _ in range(2):
            login = LoginAttempt(
                user_id=test_user.id,
                attempt_time=datetime.utcnow().replace(hour=unusual_hour),
                success=True,
                ip_address='127.0.0.1'
            )
            db.session.add(login)
        
        db.session.commit()

        print("\nTesting anomaly detection...")
        print(f"Total login attempts created: {len(normal_hours) + 2}")
        
        # Test detection during normal hours
        normal_result = check_login_time_anomaly(test_user)
        print(f"\nTest 1 - Normal hours login: {'Anomaly detected' if normal_result else 'No anomaly'}")

        # Force current time to 1 AM UTC for testing
        app.config['TESTING_HOUR'] = 1
        unusual_result = check_login_time_anomaly(test_user)
        print(f"\nTest 2 - Unusual hours login: {'Anomaly detected' if unusual_result else 'No anomaly'}")

if __name__ == '__main__':
    test_anomaly_detection()
