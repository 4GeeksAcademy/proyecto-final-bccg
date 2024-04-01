from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    phone = db.Column(db.String(50),nullable=False)
    location = db.Column(db.String(100),nullable=False)
    is_active = db.Column(db.Boolean(), unique=False, nullable=False)

    # Define relationship with Reviews
    reviews = db.relationship('Review', backref='user', lazy=True)
    favorites = db.relationship('Favorites', backref='user', lazy=True)

    def __repr__(self):
        return f'<User {self.email}>'

    def serialize(self):
        return {
            "id": self.id,
            "email": self.email,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "phone": self.phone,
            "location": self.location
        }

class Books(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(50), unique=True, nullable=False)
    author_name = db.Column(db.String(50), nullable=False)
    first_publish_year = db.Column(db.Integer, nullable=True)
    languages = db.Column(db.String(25), nullable=False)
    publishers = db.Column(db.Integer, nullable=True)
    publisher_places = db.Column(db.Integer, nullable=True)
    typeOfBook = db.Column(db.String(15))
    
    # Define relationship with Reviews
    reviews = db.relationship('Review', backref='book', lazy=True)
    favorites = db.relationship('Favorites', backref='book', lazy=True)

    def __repr__(self):
        return f"<Books(title='{self.title}', author='{self.author_name}', publish year='{self.first_publish_year}')>"
    
    def serialize(self):
        return {
            "id": self.id,
            "title": self.title,
            "author_name": self.author_name
        }

class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(500), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey('books.id'), nullable=False)

    def __repr__(self):
        return f"<Review(user_id='{self.user_id}', book_id='{self.book_id}', content='{self.content}')>"

class Favorites(db.Model):
    __tablename__ = "favorites"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey('books.id'), nullable=False)
    
    def __repr__(self):
        return f"<Favorites(user_id='{self.user_id}', book_id='{self.book_id}')>"
