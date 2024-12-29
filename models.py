from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone_number = db.Column(db.String(20))
    password = db.Column(db.String(60), nullable=False) # Store hash, not plain text
    is_paid = db.Column(db.Boolean, default=False)
    reset_token = db.Column(db.String(100), nullable=True)

    def __repr__(self):
        return f"User('{self.name}', '{self.email}')"