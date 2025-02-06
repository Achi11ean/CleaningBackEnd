from flask import Flask, jsonify, request, make_response, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, verify_jwt_in_request, decode_token
from flask_migrate import Migrate
import os
from flask_cors import CORS, cross_origin  # Import Flask-CORS
import json

from werkzeug.utils import secure_filename
from datetime import timedelta, datetime  # Add datetime here
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import smtplib
from pytz import timezone
import re
from dotenv import load_dotenv
app = Flask(__name__)
from flask_cors import CORS

CORS(app, supports_credentials=True, resources={r"/*": {"origins": os.getenv("CORS_ORIGINS", "*").split(",")}})
def token_required(f):
    def wrapper(*args, **kwargs):
        if request.path.startswith('/uploads'):
            return f(*args, **kwargs)
        token = request.headers.get('Authorization')
        if not token:
            return {"message": "No token provided"}, 401
        return f(*args, **kwargs)
    return wrapper

@app.route('/uploads/<path:filename>')
def serve_uploads(filename):
    # Serve files from 'uploads' directory
    return send_from_directory('uploads', filename)
load_dotenv()

# Configuration
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=12)
          


# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
# Public endpoints that don't require tokens
@app.before_request
def before_request():
    """
    Global token verification applied before each request.
    Skips validation for OPTIONS requests and public routes.
    """
        # Skip token validation for CORS preflight
    if request.method == "OPTIONS":
        return None
    # Print incoming request details for debugging
    print(f"Incoming request method: {request.method}")
    print(f"Incoming request path: {request.path}")
    print(f"Authorization Header: {request.headers.get('Authorization')}")
    if request.path.startswith("/uploads") or "/packages" in request.path:
            print(f"Skipping token validation for /uploads or matching path: {request.path}")
            return None  # Skip validation for /uploads
    # Allow Flask-CORS to handle OPTIONS preflight requests

    if request.endpoint and "jwt_required" in str(app.view_functions[request.endpoint]):
        return  # Skip if `@jwt_required` is already applied
    # List of public paths that don't require authentication
    public_paths = [
        "/signin", "/forgot_password", "/reset-password",
        "/api/gallery", "/api/contact", "/uploads", "/api/packages", "/api/reviews", "/api/inquiries", "/api/earnings", "/api/one_time_cleanings", "/api/recurring_payments", "/api/recurring_paid", "/api/cleaning_dates_summary", "/api/total_paid_cleanings_summary", "api/old_records", "api/cleanup_old_records", "/api/delete_old_records"
    ]

    # Check if request path matches any public path
    if any(request.path.startswith(path) for path in public_paths):
        print(f"Public path matched: {request.path}. Skipping token validation.")
        return  # Skip token validation for public paths

    print("Token validation required for this request.")
    if request.path.startswith("/api/packages") and request.method == "GET":
        return
    if request.method == "GET" and request.path == "/api/reviews":
        print(f"Public GET request matched: {request.path}. Skipping token validation.")
        return

    # Extract the Authorization header
    token = request.headers.get('Authorization', '')
    if not token or " " not in token:
        print("No token provided, returning 401")
        return jsonify({'error': 'Token is missing'}), 401

    # Verify and decode the token
    try:
        verify_jwt_in_request()
        payload = get_jwt_identity()
        print(f"Token successfully verified. Payload: {payload}")
        request.user_id = payload
    except Exception as e:
        print(f"Token validation failed: {e}")
        return jsonify({'error': 'Invalid or expired token'}), 401

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)  # Add email field
    password_hash = db.Column(db.String(128), nullable=False)

    @property
    def password(self):
        raise AttributeError("Password is not readable.")

    @password.setter
    def password(self, plaintext_password):
        self.password_hash = bcrypt.generate_password_hash(plaintext_password).decode("utf-8")

    def verify_password(self, plaintext_password):
        return bcrypt.check_password_hash(self.password_hash, plaintext_password)


from flask import request, jsonify
from sqlalchemy.exc import IntegrityError

@app.route('/signup', methods=['POST'])
def signup():
    # Parse data from the request
    data = request.get_json()

    # Validate the data
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")

    if not username or not email or not password:
        return jsonify({"message": "Missing required fields"}), 400

    # Check if user already exists
    user = User.query.filter_by(email=email).first()
    if user:
        return jsonify({"message": "Email already registered"}), 400

    user = User.query.filter_by(username=username).first()
    if user:
        return jsonify({"message": "Username already taken"}), 400

    # Create a new user
    new_user = User(username=username, email=email)
    new_user.password = password  # This will hash the password

    # Add the user to the database
    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"message": "User created successfully"}), 201
    except IntegrityError:
        db.session.rollback()
        return jsonify({"message": "Error creating user"}), 500


# Route for Admin Sign-in
@app.route('/signin', methods=['POST'])
def signin():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    admin_user = User.query.filter_by(username=username).first()
    if not admin_user or not admin_user.verify_password(password):
        return jsonify({"error": "Invalid credentials"}), 401

    # Generate a JWT token
    access_token = create_access_token(identity=admin_user.id)
    return jsonify({"message": "Sign-in successful!", "token": access_token}), 200


@app.route('/admin-dashboard', methods=['GET'])
@jwt_required()
def admin_dashboard():
    current_user_id = get_jwt_identity()
    print(f"User ID from Token: {current_user_id}")

    user = User.query.get(current_user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    return jsonify({"id": user.id, "username": user.username, "email": user.email}), 200

class Gallery(db.Model):
    __tablename__ = "gallery"

    id = db.Column(db.Integer, primary_key=True)
    image_url = db.Column(db.String(500), nullable=False)
    caption = db.Column(db.String(500), nullable=True)
    category = db.Column(db.String(50), nullable=True)
    created_at = db.Column(db.DateTime, default=db.func.now(), nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "image_url": self.image_url,
            "caption": self.caption,
            "category": self.category,
            "created_at": self.created_at.strftime("%Y-%m-%d %H:%M:%S")
        }





# Route: Upload a Photo to the Gallery
# Route: Add a Photo URL to the Gallery
@app.post('/api/gallery/upload')
@jwt_required()
def upload_photo():
    current_user_id = get_jwt_identity()

    print(f"Current user ID: {current_user_id}")  # Debugging line

    """
    Accept an image URL and add it to the gallery.
    """
    data = request.get_json()

    # Extract fields from the request body
    image_url = data.get("image_url")
    caption = data.get("caption", "")
    category = data.get("category", "Uncategorized")

    # Validate that image_url is provided
    if not image_url or not image_url.startswith(("http://", "https://")):
        return jsonify({"error": "Invalid or missing image URL."}), 400

    # Add record to the database
    new_photo = Gallery(
        image_url=image_url,  # Use the provided URL
        caption=caption,
        category=category,
    )
    db.session.add(new_photo)
    db.session.commit()

    return jsonify({"message": "Photo added successfully!", "photo": new_photo.to_dict()}), 201


# Route: Fetch All Gallery Photos
@app.get('/api/gallery')
def get_gallery():
    """
    Fetch all gallery images with optional category or photo_type filtering.
    """
    category = request.args.get("category", None)
    query = Gallery.query

    if category:
        query = query.filter(Gallery.category.ilike(f"%{category}%"))


    photos = query.all()
    return jsonify([photo.to_dict() for photo in photos]), 200



# Route: Delete a Photo
@app.delete('/api/gallery/<int:photo_id>')
@jwt_required()
def delete_photo(photo_id):
    """
    Delete a photo from the gallery.
    """
    photo = Gallery.query.get(photo_id)
    if not photo:
        return jsonify({"error": "Photo not found"}), 404

    # Remove the record from the database
    db.session.delete(photo)
    db.session.commit()

    return jsonify({"message": "Photo deleted successfully"}), 200

#--------------------------------------------------------------------------------#
class Review(db.Model):
    __tablename__ = "reviews"

    id = db.Column(db.Integer, primary_key=True)
    photo_url = db.Column(db.String(500), nullable=True)  # Store the image URL directly
    reviewer_name = db.Column(db.String(50), nullable=False)
    rating = db.Column(db.Integer, nullable=False)  # Rating out of 5
    comment = db.Column(db.String(600), nullable=True)
    created_at = db.Column(db.DateTime, default=db.func.now(), nullable=False)
    is_approved = db.Column(db.Boolean, default=False, nullable=False)  # New field

    def to_dict(self):
        return {
            "id": self.id,
            "photo_url": self.photo_url, 
            "reviewer_name": self.reviewer_name,
            "rating": self.rating,
            "comment": self.comment,
            "is_approved": self.is_approved, 
            "created_at": self.created_at.strftime("%Y-%m-%d %H:%M:%S")
        }

@app.route('/api/reviews', methods=['POST'])
def add_review():
    """
    Add a review. The photo_url is optional.
    """
    data = request.get_json()
    photo_url = data.get("photo_url", "")  # Optional field for the image URL
    reviewer_name = data.get("reviewer_name")
    rating = data.get("rating")
    comment = data.get("comment", "")

    # Validate inputs
    if not reviewer_name or not rating:
        return jsonify({"error": "Reviewer name and rating are required."}), 400
    if not (1 <= int(rating) <= 5):
        return jsonify({"error": "Rating must be between 1 and 5."}), 400

    # Create and save the review
    review = Review(
        photo_url=photo_url,  # Store the image URL directly
        reviewer_name=reviewer_name,
        rating=int(rating),
        comment=comment
    )
    db.session.add(review)
    db.session.commit()

    return jsonify({"message": "Review added successfully!", "review": review.to_dict()}), 201

@app.get('/api/reviews/pending')
@jwt_required()
def get_pending_reviews():
    """
    Get all reviews that are pending approval.
    Admin access required.
    """
    # Check if the user is an admin (add your logic for admin verification)
    current_user_id = get_jwt_identity()
    # Example: Add logic to check if the user is an admin
    # user = User.query.get(current_user_id)
    # if not user.is_admin:
    #     return jsonify({"error": "Admin access required."}), 403

    # Query for pending reviews
    pending_reviews = Review.query.filter_by(is_approved=False).all()

    return jsonify([review.to_dict() for review in pending_reviews]), 200


@app.get('/api/reviews')
def get_reviews():
    """
    Get all approved reviews. Optionally filter by photo_url.
    """
    photo_url = request.args.get("photo_url", None)  # Optional query parameter

    query = Review.query.filter_by(is_approved=True)  # Only fetch approved reviews
    if photo_url:
        query = query.filter_by(photo_url=photo_url)

    reviews = query.all()
    return jsonify([review.to_dict() for review in reviews]), 200
@app.patch('/api/reviews/<int:review_id>/approve')
@jwt_required()  # Admin access only
def approve_review(review_id):
    """
    Approve a specific review by its ID.
    """
    # Check user permissions if needed (ensure admin access)
    current_user_id = get_jwt_identity()
    # Add logic to confirm if the user is an admin

    # Find the review
    review = Review.query.get(review_id)
    if not review:
        return jsonify({"error": "Review not found."}), 404

    # Approve the review
    review.is_approved = True
    db.session.commit()

    return jsonify({"message": "Review approved successfully!", "review": review.to_dict()}), 200


@app.delete('/api/reviews/<int:review_id>')
@jwt_required()
def delete_review(review_id):
    """
    Delete a specific review by its ID.
    """
    # Find the review by ID
    review = Review.query.get(review_id)

    # Check if the review exists
    if not review:
        return jsonify({"error": "Review not found."}), 404

    # Log the photo_url for debugging or tracking purposes (optional)
    print(f"Deleting review with ID: {review_id}, associated photo URL: {review.photo_url}")

    # Delete the review
    db.session.delete(review)
    db.session.commit()

    return jsonify({"message": f"Review with ID {review_id} deleted successfully."}), 200

@app.patch('/api/reviews/<int:review_id>')
@jwt_required()
def update_review(review_id):
    """
    Update specific fields of a review by its ID.
    Admin access required.
    """
    # Check for admin access (add your admin verification logic)
    current_user_id = get_jwt_identity()

    # Find the review
    review = Review.query.get(review_id)
    if not review:
        return jsonify({"error": "Review not found."}), 404

    data = request.get_json()

    # Update fields if provided
    if "reviewer_name" in data:
        review.reviewer_name = data["reviewer_name"]
    if "rating" in data:
        if not (1 <= int(data["rating"]) <= 5):
            return jsonify({"error": "Rating must be between 1 and 5."}), 400
        review.rating = int(data["rating"])
    if "comment" in data:
        review.comment = data["comment"]
    if "photo_url" in data:
        review.photo_url = data["photo_url"]

    # Automatically set the review to pending when updated
    review.is_approved = False

    db.session.commit()

    return jsonify({"message": "Review updated successfully and marked as pending!", "review": review.to_dict()}), 200

#----------------------------------------------------------------------------------------------------

class Inquiry(db.Model):
    __tablename__ = "inquiries"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    phone_number = db.Column(db.String(15), nullable=True)  
    call_or_text = db.Column(db.String(10), nullable=False)  
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(50), nullable=False, default="New Inquiry")  # Updated default value
    submitted_at = db.Column(db.DateTime, default=db.func.now(), nullable=False)


    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "email": self.email,
            "phone_number": self.phone_number,
            "call_or_text": self.call_or_text,
            "description": self.description,
            "submitted_at": self.submitted_at.strftime("%Y-%m-%d %H:%M:%S"),
            "status": self.status,  # Add this line


        }
@app.post('/api/contact')
def submit_inquiry():
    """
    Submit a user inquiry and notify the admin via email.
    """
    data = request.get_json()

    # Validate required fields
    required_fields = ['name', 'email', 'call_or_text', 'description']
    if not all(data.get(field) for field in required_fields):
        return jsonify({"error": f"Missing required fields: {', '.join(required_fields)}"}), 400

    # Validate call_or_text
    call_or_text = data.get('call_or_text').lower()
    if call_or_text not in ["call", "text"]:
        return jsonify({"error": "Invalid value for 'call_or_text'. Must be 'call' or 'text'."}), 400

    # Validate email format
    email = data.get('email')
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return jsonify({"error": "Invalid email format"}), 400

    # Create new inquiry
    new_inquiry = Inquiry(
        name=data.get('name'),
        email=email,
        phone_number=data.get('phone_number'),
        call_or_text=call_or_text,
        description=data.get('description'),
        # Do not pass 'status' here; let the database handle the default
    )

    db.session.add(new_inquiry)
    db.session.commit()

    # Format the submission time
    local_tz = timezone("US/Eastern")  # Replace "US/Eastern" with your actual timezone
    submitted_at_local = new_inquiry.submitted_at.replace(tzinfo=timezone("UTC")).astimezone(local_tz)

    # Send email to admin
    try:
        admin_email = os.getenv("ADMIN_EMAIL")  # Admin email from environment variable
        subject = f"New Inquiry from {new_inquiry.name}"
        body = f"""
        <html>
        <body>
            <div>
            <h2>📧 New Inquiry Received</h2>
            <p><strong>Name:</strong> {new_inquiry.name}</p>
            <p><strong>Email:</strong> {new_inquiry.email}</p>
            <p><strong>Phone Number:</strong> {new_inquiry.phone_number or "N/A"}</p>
            <p><strong>Contact Preference:</strong> {new_inquiry.call_or_text.capitalize()}</p>
            <p><strong>Description:</strong> {new_inquiry.description}</p>
            <p>Submitted on {submitted_at_local.strftime('%A, %B %d, %Y %I:%M %p')}</p>
            </div>
        </body>
        </html>
        """

        send_email(
            recipient=admin_email,
            subject=subject,
            body=body
        )
    except Exception as e:
        print(f"Failed to send email: {str(e)}")
        return jsonify({"error": "Inquiry submitted but failed to notify the admin."}), 500

    return jsonify({"message": "Inquiry submitted successfully.", "inquiry": new_inquiry.to_dict()}), 201



def send_email(recipient, subject, body, background_image_url=None):
    """
    Sends a simple email with optional background image.
    """
    sender_email = os.getenv('EMAIL_ADDRESS')
    sender_password = os.getenv('EMAIL_PASSWORD')
    smtp_server = os.getenv('SMTP_SERVER')
    smtp_port = int(os.getenv('SMTP_PORT', 587))

    # Build plain-text body
    text_body = body  # Use the full body content

    msg = MIMEMultipart("alternative")
    msg["From"] = sender_email
    msg["To"] = recipient
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "html"))

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.send_message(msg)
        print(f"Email sent to {recipient}")
    except Exception as e:
        print(f"Email error: {str(e)}")
        raise e
@app.get('/api/inquiries/<int:inquiry_id>')
def get_inquiry(inquiry_id):
    """
    Fetch a single inquiry by its ID.
    """
    inquiry = Inquiry.query.get(inquiry_id)
    if not inquiry:
        return jsonify({"error": "Inquiry not found."}), 404

    return jsonify(inquiry.to_dict()), 200
@app.patch('/api/inquiries/<int:inquiry_id>')
def update_inquiry(inquiry_id):
    print(f"PATCH request received for Inquiry ID: {inquiry_id}")

    data = request.get_json()
    print("Received data:", data)

    inquiry = Inquiry.query.get(inquiry_id)
    if not inquiry:
        print(f"Inquiry with ID {inquiry_id} not found.")
        return jsonify({"error": "Inquiry not found."}), 404

    # Update fields if provided
    if "name" in data:
        inquiry.name = data["name"]
    if "email" in data:
        email = data["email"]
        if not re.match(r"^[^@]+@[^@]+\.[^@]+$", email):
            print(f"Invalid email format: {email}")
            return jsonify({"error": "Invalid email format"}), 400
        inquiry.email = email
    if "phone_number" in data:
        inquiry.phone_number = data["phone_number"]
    if "call_or_text" in data:
        call_or_text = data["call_or_text"].lower()
        if call_or_text not in ["call", "text"]:
            print(f"Invalid call_or_text value: {call_or_text}")
            return jsonify({"error": "Invalid value for 'call_or_text'. Must be 'call' or 'text'."}), 400
        inquiry.call_or_text = call_or_text
    if "description" in data:
        inquiry.description = data["description"]
    if "status" in data:
        status = data["status"].strip().lower()
        allowed_statuses = {"new inquiry", "booked", "contacted", "paused", "completed"}
        if status not in allowed_statuses:
            print(f"Invalid status value: {status}")
            return jsonify({"error": f"Invalid status. Allowed values: {', '.join(allowed_statuses)}"}), 400
        inquiry.status = status.title()  # Store in Title Case

    # Commit the changes to the database
    try:
        db.session.commit()
        updated_inquiry = Inquiry.query.get(inquiry_id)  # Verify changes persisted
        print(f"Updated Inquiry from DB: {updated_inquiry.to_dict()}")
        return jsonify({"message": "Inquiry updated successfully.", "inquiry": updated_inquiry.to_dict()}), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error updating inquiry: {e}")
        return jsonify({"error": "Failed to update inquiry."}), 500

@app.get('/api/inquiries')
def get_inquiries():
    """
    Fetch all client inquiries with optional filtering by name, phone_number, or status.
    """
    try:
        # Get query parameters from the request
        name = request.args.get("name", "").strip()
        phone_number = request.args.get("phone_number", "").strip()
        status = request.args.get("status", "").strip().lower()  # Convert to lowercase for consistency

        # Build query dynamically
        query = Inquiry.query

        if name:
            query = query.filter(Inquiry.name.ilike(f"%{name}%"))  # Case-insensitive search
        if phone_number:
            query = query.filter(Inquiry.phone_number.ilike(f"%{phone_number}%"))
        if status:
            query = query.filter(Inquiry.status.ilike(f"%{status}%"))  # Case-insensitive filter for status

        # Execute query with sorting
        inquiries = query.order_by(Inquiry.submitted_at.desc()).all()

        return jsonify([inquiry.to_dict() for inquiry in inquiries]), 200
    except Exception as e:
        print(f"Error fetching inquiries: {e}")
        return jsonify({"error": "Failed to fetch inquiries."}), 500

@app.delete('/api/inquiries/<int:inquiry_id>')
def delete_inquiry(inquiry_id):
    """
    Delete an inquiry by ID.
    """
    # Fetch the inquiry by ID
    inquiry = Inquiry.query.get(inquiry_id)
    print(f"Attempting to delete inquiry with ID: {inquiry_id}")

    if not inquiry:
        return jsonify({"error": "Inquiry not found."}), 404

    try:
        # Delete the inquiry
        db.session.delete(inquiry)
        db.session.commit()
        return jsonify({"message": f"Inquiry with ID {inquiry_id} deleted successfully."}), 200
    except Exception as e:
        print(f"Error deleting inquiry: {e}")
        return jsonify({"error": "Failed to delete the inquiry."}), 500

class OneTimeCleaning(db.Model):
    __tablename__ = "one_time_cleanings"

    id = db.Column(db.Integer, primary_key=True)
    inquiry_id = db.Column(db.Integer, db.ForeignKey('inquiries.id'), nullable=False)  # Foreign key to Inquiry
    date_time = db.Column(db.DateTime, nullable=False)  # Date and time for the cleaning
    amount = db.Column(db.Float, nullable=False)  # Cleaning amount
    paid = db.Column(db.Boolean, nullable=False, default=False)  # Whether the cleaning is paid
    notes = db.Column(db.Text, nullable=True)  # Notes for the cleaning job

    inquiry = db.relationship('Inquiry', backref='one_time_cleanings')  # Relationship to Inquiry

    def to_dict(self):
        return {
            "id": self.id,
            "inquiry_id": self.inquiry_id,
            "inquiry_name": self.inquiry.name,  # Reference the related inquiry's name
            "date_time": self.date_time.strftime("%Y-%m-%d %H:%M:%S"),
            "amount": self.amount,
            "paid": self.paid,
            "notes": self.notes,  # Include notes in the response

        }
@app.post('/api/one_time_cleanings')
def create_one_time_cleaning():
    """
    Create a new one-time cleaning service.
    """
    data = request.get_json()
    print(request.json)  # Debugging

    # Validate required fields
    required_fields = ['inquiry_id', 'date_time', 'amount']
    if not all(data.get(field) for field in required_fields):
        return jsonify({"error": f"Missing required fields: {', '.join(required_fields)}"}), 400

    # Validate inquiry exists
    inquiry = Inquiry.query.get(data['inquiry_id'])
    if not inquiry:
        return jsonify({"error": "Inquiry not found."}), 404

    # Parse date_time
    try:
        date_time = datetime.strptime(data['date_time'], "%Y-%m-%dT%H:%M")  # ISO 8601 format
    except ValueError:
        return jsonify({"error": "Invalid date format. Use 'YYYY-MM-DDTHH:MM'."}), 400

    # Create a new OneTimeCleaning entry
    one_time_cleaning = OneTimeCleaning(
        inquiry_id=data['inquiry_id'],
        date_time=date_time,
        amount=data['amount'],
        paid=data.get('paid', False),
        notes=data.get('notes', None)  # Add notes if provided
  
    )

    try:
        db.session.add(one_time_cleaning)
        db.session.commit()
        return jsonify({"message": "One-time cleaning created successfully.", "one_time_cleaning": one_time_cleaning.to_dict()}), 201
    except Exception as e:
        print(f"Error creating one-time cleaning: {e}")
        return jsonify({"error": "Failed to create one-time cleaning."}), 500
    
@app.patch('/api/one_time_cleanings/<int:cleaning_id>')
def update_one_time_cleaning(cleaning_id):
    """
    Update an existing one-time cleaning service.
    """
    data = request.get_json()
    print(f"Received PATCH request payload: {data}")  # Debugging

    # Fetch the cleaning entry by ID
    one_time_cleaning = OneTimeCleaning.query.get(cleaning_id)
    if not one_time_cleaning:
        return jsonify({"error": "One-time cleaning not found."}), 404

    print(f"Initial cleaning data: {one_time_cleaning.to_dict()}")  # Debugging

    # Update `date_time` only if it's different
    if "date_time" in data and data["date_time"] is not None:
        try:
            # Handle both 'YYYY-MM-DD HH:MM:SS' and 'YYYY-MM-DDTHH:MM' formats
            if "T" in data["date_time"]:
                new_date_time = datetime.strptime(data["date_time"], "%Y-%m-%dT%H:%M")
            else:
                new_date_time = datetime.strptime(data["date_time"], "%Y-%m-%d %H:%M:%S")

            if new_date_time != one_time_cleaning.date_time:
                print(f"Updating date_time from {one_time_cleaning.date_time} to {new_date_time}")  # Debugging
                one_time_cleaning.date_time = new_date_time
        except ValueError:
            print("Invalid date_time format provided.")  # Debugging
            return jsonify({"error": "Invalid date format. Use 'YYYY-MM-DD HH:MM:SS' or 'YYYY-MM-DDTHH:MM'."}), 400

    # Update `amount` only if it's different
    if "amount" in data and data["amount"] is not None:
        try:
            new_amount = float(data["amount"])
            if new_amount != one_time_cleaning.amount:
                print(f"Updating amount from {one_time_cleaning.amount} to {new_amount}")  # Debugging
                one_time_cleaning.amount = new_amount
        except ValueError:
            print("Invalid amount provided.")  # Debugging
            return jsonify({"error": "Invalid amount. Must be a number."}), 400

    # Update `paid` only if it's different
    if "paid" in data and data["paid"] is not None:
        new_paid_status = bool(data["paid"])
        if new_paid_status != one_time_cleaning.paid:
            print(f"Updating paid status from {one_time_cleaning.paid} to {new_paid_status}")  # Debugging
            one_time_cleaning.paid = new_paid_status

    # Update `notes` only if it's different
    if "notes" in data and data["notes"] is not None:
        new_notes = data["notes"]
        if new_notes != one_time_cleaning.notes:
            print(f"Updating notes from {one_time_cleaning.notes} to {new_notes}")  # Debugging
            one_time_cleaning.notes = new_notes

    # Commit the changes to the database
    try:
        print(f"Final cleaning data before commit: {one_time_cleaning.to_dict()}")  # Debugging
        db.session.commit()
        print("Changes successfully committed to the database.")  # Debugging
        return jsonify({
            "message": "One-time cleaning updated successfully.",
            "one_time_cleaning": one_time_cleaning.to_dict()
        }), 200
    except Exception as e:
        print(f"Error updating one-time cleaning: {e}")
        return jsonify({"error": "Failed to update one-time cleaning."}), 500

@app.delete('/api/one_time_cleanings/<int:cleaning_id>')
def delete_one_time_cleaning(cleaning_id):
    """
    Delete an existing one-time cleaning service.
    """
    # Fetch the cleaning entry by ID
    one_time_cleaning = OneTimeCleaning.query.get(cleaning_id)
    if not one_time_cleaning:
        return jsonify({"error": "One-time cleaning not found."}), 404

    try:
        # Delete the cleaning entry
        db.session.delete(one_time_cleaning)
        db.session.commit()
        return jsonify({"message": f"One-time cleaning with ID {cleaning_id} deleted successfully."}), 200
    except Exception as e:
        print(f"Error deleting one-time cleaning: {e}")
        return jsonify({"error": "Failed to delete one-time cleaning."}), 500
    
@app.get('/api/one_time_cleanings')
def get_all_one_time_cleanings():
    """
    Fetch all one-time cleaning services with optional filters for name and paid status.
    """
    try:
        # Get query parameters
        name = request.args.get("name", "").strip()
        paid = request.args.get("paid", "").strip()

        # Build the base query
        query = OneTimeCleaning.query.join(Inquiry)

        # Apply filters based on query parameters
        if name:
            query = query.filter(Inquiry.name.ilike(f"%{name}%"))  # Case-insensitive search for name
        if paid.lower() in ["true", "false"]:
            query = query.filter(OneTimeCleaning.paid == (paid.lower() == "true"))

        # Fetch the filtered results
        one_time_cleanings = query.order_by(OneTimeCleaning.date_time.desc()).all()

        # Serialize and return the results
        return jsonify([cleaning.to_dict() for cleaning in one_time_cleanings]), 200
    except Exception as e:
        print(f"Error fetching one-time cleanings: {e}")
        return jsonify({"error": "Failed to fetch one-time cleanings."}), 500


@app.get('/api/one_time_cleanings/<int:cleaning_id>')
def get_one_time_cleaning(cleaning_id):
    """
    Fetch a single one-time cleaning service by its ID.
    """
    one_time_cleaning = OneTimeCleaning.query.get(cleaning_id)
    if not one_time_cleaning:
        return jsonify({"error": "One-time cleaning not found."}), 404

    return jsonify(one_time_cleaning.to_dict()), 200


class RecurringPayment(db.Model):
    __tablename__ = "recurring_payments"

    id = db.Column(db.Integer, primary_key=True)
    inquiry_id = db.Column(db.Integer, db.ForeignKey('inquiries.id'), nullable=False)  # Foreign key to Inquiry
    amount = db.Column(db.Float, nullable=False)  # Amount for the recurring payment
    frequency = db.Column(db.String(250), nullable=False)  # Frequency of the payment (e.g., "weekly", "monthly")
    notes = db.Column(db.String(255), nullable=True)  # Optional notes for the recurring payment

    inquiry = db.relationship('Inquiry', backref='recurring_payments')  # Relationship to Inquiry

    def to_dict(self):
        return {
            "id": self.id,
            "inquiry_id": self.inquiry_id,
            "inquiry_name": self.inquiry.name,  # Reference the related inquiry's name
            "amount": self.amount,
            "frequency": self.frequency,
            "notes": self.notes
        }

@app.post('/api/recurring_payments')
def create_recurring_payment():
    """
    Create a new recurring payment.
    """
    data = request.get_json()

    # Validate required fields
    required_fields = ['inquiry_id', 'amount', 'frequency']
    if not all(data.get(field) for field in required_fields):
        return jsonify({"error": f"Missing required fields: {', '.join(required_fields)}"}), 400

    # Validate inquiry exists
    inquiry = Inquiry.query.get(data['inquiry_id'])
    if not inquiry:
        return jsonify({"error": "Inquiry not found."}), 404

    # Create a new RecurringPayment entry
    recurring_payment = RecurringPayment(
        inquiry_id=data['inquiry_id'],
        amount=data['amount'],
        frequency=data['frequency'],  # Accept any string value for frequency
        notes=data.get('notes')  # Optional field
    )

    try:
        db.session.add(recurring_payment)
        db.session.commit()
        return jsonify({
            "message": "Recurring payment created successfully.",
            "recurring_payment": recurring_payment.to_dict()
        }), 201
    except Exception as e:
        print(f"Error creating recurring payment: {e}")
        return jsonify({"error": "Failed to create recurring payment."}), 500

@app.patch('/api/recurring_payments/<int:payment_id>')
def update_recurring_payment(payment_id):
    """
    Update an existing recurring payment.
    """
    data = request.get_json()

    # Fetch the payment entry by ID
    recurring_payment = RecurringPayment.query.get(payment_id)
    if not recurring_payment:
        return jsonify({"error": "Recurring payment not found."}), 404

    # Update fields if provided
    if "amount" in data:
        try:
            recurring_payment.amount = float(data["amount"])
        except ValueError:
            return jsonify({"error": "Invalid amount. Must be a number."}), 400

    if "frequency" in data:
        recurring_payment.frequency = data["frequency"]  # Accept any string value for frequency

    if "notes" in data:
        recurring_payment.notes = data["notes"]

    # Update the inquiry_id if provided
    if "inquiry_id" in data:
        # Optionally, check if the provided inquiry_id is valid
        inquiry = Inquiry.query.get(data["inquiry_id"])
        if not inquiry:
            return jsonify({"error": "Inquiry not found."}), 404
        recurring_payment.inquiry_id = data["inquiry_id"]

    # Commit the changes to the database
    try:
        db.session.commit()
        return jsonify({
            "message": "Recurring payment updated successfully.",
            "recurring_payment": recurring_payment.to_dict()
        }), 200
    except Exception as e:
        print(f"Error updating recurring payment: {e}")
        return jsonify({"error": "Failed to update recurring payment."}), 500

@app.delete('/api/recurring_payments/<int:payment_id>')
def delete_recurring_payment(payment_id):
    """
    Delete an existing recurring payment.
    """
    # Fetch the payment entry by ID
    recurring_payment = RecurringPayment.query.get(payment_id)
    if not recurring_payment:
        return jsonify({"error": "Recurring payment not found."}), 404

    try:
        # Delete the payment entry
        db.session.delete(recurring_payment)
        db.session.commit()
        return jsonify({"message": f"Recurring payment with ID {payment_id} deleted successfully."}), 200
    except Exception as e:
        print(f"Error deleting recurring payment: {e}")
        return jsonify({"error": "Failed to delete recurring payment."}), 500

@app.get('/api/recurring_payments')
def get_all_recurring_payments():
    """
    Fetch all recurring payments with optional search by name or frequency.
    """
    try:
        # Get query parameters
        name = request.args.get("name", "").strip()
        frequency = request.args.get("frequency", "").strip()

        # Build the query
        query = RecurringPayment.query.join(Inquiry)

        if name:
            query = query.filter(Inquiry.name.ilike(f"%{name}%"))  # Case-insensitive search for name
        if frequency:
            query = query.filter(RecurringPayment.frequency.ilike(f"%{frequency}%"))  # Case-insensitive search for frequency

        # Fetch results
        recurring_payments = query.order_by(RecurringPayment.id.desc()).all()

        return jsonify([payment.to_dict() for payment in recurring_payments]), 200
    except Exception as e:
        print(f"Error fetching recurring payments: {e}")
        return jsonify({"error": "Failed to fetch recurring payments."}), 500


@app.get('/api/recurring_payments/<int:payment_id>')
def get_recurring_payment(payment_id):
    """
    Fetch a single recurring payment by its ID.
    """
    recurring_payment = RecurringPayment.query.get(payment_id)
    if not recurring_payment:
        return jsonify({"error": "Recurring payment not found."}), 404

    return jsonify(recurring_payment.to_dict()), 200


class RecurringPaid(db.Model):
    __tablename__ = "recurring_paid"

    id = db.Column(db.Integer, primary_key=True)
    recurring_payment_id = db.Column(db.Integer, db.ForeignKey('recurring_payments.id'), nullable=False)  # Foreign key to RecurringPayment
    dates_related = db.Column(db.String(255), nullable=True)  # Dates the payment relates to
    amount_paid = db.Column(db.Float, nullable=False)  # Amount paid for this occurrence
    submitted_at = db.Column(db.DateTime, default=db.func.now(), nullable=False)  # Timestamp for when the payment was submitted
    notes = db.Column(db.String(255), nullable=True)  # Optional notes

    recurring_payment = db.relationship('RecurringPayment', backref='payments_made')  # Relationship to RecurringPayment

    def to_dict(self):
        return {
            "id": self.id,
            "recurring_payment_id": self.recurring_payment_id,
            "recurring_payment_name": self.recurring_payment.inquiry.name,  # Inquiry name from RecurringPayment
            "dates_related": self.dates_related,
            "amount_paid": self.amount_paid,
            "submitted_at": self.submitted_at.strftime("%Y-%m-%d %H:%M:%S"),
            "notes": self.notes
        }
@app.post('/api/recurring_paid')
def create_recurring_paid():
    """
    Create a new recurring payment record.
    """
    data = request.get_json()

    # Validate required fields
    required_fields = ['recurring_payment_id', 'amount_paid']
    if not all(data.get(field) for field in required_fields):
        return jsonify({"error": f"Missing required fields: {', '.join(required_fields)}"}), 400

    # Validate recurring payment exists
    recurring_payment = RecurringPayment.query.get(data['recurring_payment_id'])
    if not recurring_payment:
        return jsonify({"error": "Recurring payment not found."}), 404

    # Create a new RecurringPaid entry
    recurring_paid = RecurringPaid(
        recurring_payment_id=data['recurring_payment_id'],
        dates_related=data.get('dates_related'),  # Optional
        amount_paid=data['amount_paid'],
        notes=data.get('notes')  # Optional
    )

    try:
        db.session.add(recurring_paid)
        db.session.commit()
        return jsonify({
            "message": "Recurring payment record created successfully.",
            "recurring_paid": recurring_paid.to_dict()
        }), 201
    except Exception as e:
        print(f"Error creating recurring payment record: {e}")
        return jsonify({"error": "Failed to create recurring payment record."}), 500

@app.patch('/api/recurring_paid/<int:paid_id>')
def update_recurring_paid(paid_id):
    """
    Update an existing recurring payment record.
    """
    data = request.get_json()

    # Fetch the payment entry by ID
    recurring_paid = RecurringPaid.query.get(paid_id)
    if not recurring_paid:
        return jsonify({"error": "Recurring payment record not found."}), 404

    # Update fields if provided
    if "dates_related" in data:
        recurring_paid.dates_related = data["dates_related"]

    if "amount_paid" in data:
        try:
            recurring_paid.amount_paid = float(data["amount_paid"])
        except ValueError:
            return jsonify({"error": "Invalid amount. Must be a number."}), 400

    if "notes" in data:
        recurring_paid.notes = data["notes"]

    # Commit the changes to the database
    try:
        db.session.commit()
        return jsonify({
            "message": "Recurring payment record updated successfully.",
            "recurring_paid": recurring_paid.to_dict()
        }), 200
    except Exception as e:
        print(f"Error updating recurring payment record: {e}")
        return jsonify({"error": "Failed to update recurring payment record."}), 500

@app.delete('/api/recurring_paid/<int:paid_id>')
def delete_recurring_paid(paid_id):
    """
    Delete an existing recurring payment record.
    """
    # Fetch the payment entry by ID
    recurring_paid = RecurringPaid.query.get(paid_id)
    if not recurring_paid:
        return jsonify({"error": "Recurring payment record not found."}), 404

    try:
        # Delete the payment entry
        db.session.delete(recurring_paid)
        db.session.commit()
        return jsonify({"message": f"Recurring payment record with ID {paid_id} deleted successfully."}), 200
    except Exception as e:
        print(f"Error deleting recurring payment record: {e}")
        return jsonify({"error": "Failed to delete recurring payment record."}), 500
@app.get('/api/recurring_paid')
def get_all_recurring_paid():
    """
    Fetch all recurring payment records, optionally filtered by name.
    """
    try:
        # Get the search parameter from the request query
        search_name = request.args.get("name", "").strip()

        # Build the query
        query = RecurringPaid.query.join(RecurringPayment).join(Inquiry)

        if search_name:
            # Filter by name using a case-insensitive search
            query = query.filter(Inquiry.name.ilike(f"%{search_name}%"))

        # Execute the query and order by submitted_at in descending order
        records = query.order_by(RecurringPaid.submitted_at.desc()).all()

        # Return the results as JSON
        return jsonify([record.to_dict() for record in records]), 200
    except Exception as e:
        print(f"Error fetching recurring payment records: {e}")
        return jsonify({"error": "Failed to fetch recurring payment records."}), 500

@app.get('/api/recurring_paid/<int:paid_id>')
def get_recurring_paid(paid_id):
    """
    Fetch a single recurring payment record by its ID.
    """
    recurring_paid = RecurringPaid.query.get(paid_id)
    if not recurring_paid:
        return jsonify({"error": "Recurring payment record not found."}), 404

    return jsonify(recurring_paid.to_dict()), 200

@app.get('/api/paid_cleanings_summary')
def get_paid_cleanings_summary():
    """
    Fetch all one-time cleanings with 'paid=True' and all recurring paid records, and calculate the total amount.
    """
    try:
        # Fetch all one-time cleanings where paid is True
        one_time_cleanings = OneTimeCleaning.query.filter_by(paid=True).all()
        one_time_total = sum(cleaning.amount for cleaning in one_time_cleanings)

        # Fetch all recurring paid records
        recurring_paid_records = RecurringPaid.query.all()
        recurring_total = sum(record.amount_paid for record in recurring_paid_records)

        # Calculate the overall total
        total_paid = one_time_total + recurring_total

        # Prepare response data
        response_data = {
            "one_time_cleanings": [cleaning.to_dict() for cleaning in one_time_cleanings],
            "recurring_paid_records": [record.to_dict() for record in recurring_paid_records],
            "one_time_total": one_time_total,
            "recurring_total": recurring_total,
            "total_paid": total_paid
        }

        return jsonify(response_data), 200
    except Exception as e:
        print(f"Error fetching paid cleanings summary: {e}")
        return jsonify({"error": "Failed to fetch paid cleanings summary."}), 500

@app.get('/api/cleaning_dates_summary')
def get_cleaning_dates_summary():
    """
    Fetch all one-time cleaning dates and associated inquiries along with
    recurring payment 'dates_related' and their associated inquiries.
    """
    try:
        # Fetch one-time cleanings and their associated inquiries
        one_time_cleanings = OneTimeCleaning.query.all()
        one_time_data = [
            {
                "cleaning_id": cleaning.id,
                "date_time": cleaning.date_time.strftime("%Y-%m-%d %H:%M:%S"),
                "inquiry_id": cleaning.inquiry_id,
                "inquiry_name": cleaning.inquiry.name,
                "paid": cleaning.paid,  # Include the 'paid' status
                "notes": cleaning.notes or "No notes",  # Include notes
                "phone_number": cleaning.inquiry.phone_number,  # Include phone number here

            }
            for cleaning in one_time_cleanings
        ]

        # Fetch recurring payments with 'dates_related' and their associated inquiries
        recurring_paid_records = RecurringPaid.query.all()
        recurring_paid_data = [
            {
                "recurring_paid_id": record.id,
                "dates_related": record.dates_related,
                "recurring_payment_id": record.recurring_payment_id,
                "inquiry_id": record.recurring_payment.inquiry_id,
                "inquiry_name": record.recurring_payment.inquiry.name,
                "notes": record.notes or "Recurring event, check inquiry for details.",  # Include notes
                "phone_number": record.recurring_payment.inquiry.phone_number,  # Include phone number here

            }
            for record in recurring_paid_records
        ]

        # Combine the data
        response_data = {
            "one_time_cleanings": one_time_data,
            "recurring_paid_records": recurring_paid_data
        }

        return jsonify(response_data), 200

    except Exception as e:
        print(f"Error fetching cleaning dates summary: {e}")
        return jsonify({"error": "Failed to fetch cleaning dates summary."}), 500

@app.get('/api/total_paid_cleanings_summary')
def get_total_paid_cleanings_summary():
    """
    Fetch the total amounts for paid one-time cleanings and recurring paid records.
    """
    try:
        # Calculate the total amount for paid one-time cleanings
        one_time_cleanings = OneTimeCleaning.query.filter_by(paid=True).all()
        one_time_total = sum(cleaning.amount for cleaning in one_time_cleanings)

        # Calculate the total amount for recurring paid records
        recurring_paid_records = RecurringPaid.query.all()
        recurring_total = sum(record.amount_paid for record in recurring_paid_records)

        # Prepare the summarized response
        response_data = {
            "one_time_total": one_time_total,
            "recurring_total": recurring_total,
            "total_paid": one_time_total + recurring_total
        }

        return jsonify(response_data), 200

    except Exception as e:
        print(f"Error fetching total paid cleanings summary: {e}")
        return jsonify({"error": "Failed to fetch total paid cleanings summary."}), 500


#-------------------------------------------------------------------------------

@app.route('/forgot_password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    username = data.get("username")

    # Validate user
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    # Generate reset token (valid for 1 hour)
    reset_token = create_access_token(identity=user.id, expires_delta=timedelta(hours=1))

    # Send reset email
    reset_link = f"http://localhost:5173/reset-password?token={reset_token}"
    subject = "Password Reset Request"
    body = f"""
    <html>
    <head>
        <style>
            body {{
                font-family: 'Arial', sans-serif;
                background-color: #f4f4f9;
                margin: 0;
                padding: 0;
                color: #333333;
            }}
            .container {{
                max-width: 600px;
                margin: 40px auto;
                background-color: #ffffff;
                border-radius: 10px;
                box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
                overflow: hidden;
            }}
            .header {{
                background: linear-gradient(to right, #4a90e2, #1453e4);
                color: #ffffff;
                text-align: center;
                padding: 20px 0;
            }}
            .header h1 {{
                margin: 0;
                font-size: 24px;
                font-weight: bold;
            }}
            .content {{
                padding: 30px;
                text-align: center;
            }}
            .content p {{
                font-size: 16px;
                line-height: 1.6;
            }}
            .reset-button {{
                display: inline-block;
                margin: 20px 0;
                padding: 12px 24px;
                background: #4a90e2;
                color: #ffffff;
                text-decoration: none;
                font-weight: bold;
                border-radius: 50px;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.2);
                transition: background 0.3s ease;
            }}
            .reset-button:hover {{
                background: #1453e4;
            }}
            .footer {{
                background-color: #f4f4f9;
                text-align: center;
                font-size: 12px;
                padding: 15px;
                color: #666666;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🔒 Password Reset Request</h1>
            </div>
            <div class="content">
                <p>Hello <strong>{user.username}</strong>,</p>
                <p>
                    We received a request to reset your password. Click the button below to proceed:
                </p>
                <a href="{reset_link}" class="reset-button" target="_blank">Reset Your Password</a>
                <p>If you did not request a password reset, you can safely ignore this email.</p>
                <p>For security reasons, this link will expire in 1 hour.</p>
            </div>
            <div class="footer">
                &copy; {datetime.now().year} Golden Hour Photography | All rights reserved.
            </div>
        </div>
    </body>
    </html>
    """

    try:
        send_email(user.email, subject, body)
    except Exception as e:
        return jsonify({"error": "Failed to send reset email"}), 500

    return jsonify({"message": "Password reset link has been sent to your email."}), 200

@app.post('/reset-password')
def reset_password():
    data = request.get_json()
    reset_token = request.headers.get("Authorization", "").replace("Bearer ", "")

    print(f"Token received: {reset_token}")  # Debugging line

    try:
        # Decode the token manually
        decoded_token = decode_token(reset_token)
        user_id = decoded_token.get("sub")  # Extract user ID from 'sub' field
        print(f"Decoded User ID: {user_id}")  # Debugging line
    except Exception as e:
        print(f"Token decoding failed: {str(e)}")
        return jsonify({"error": "Invalid or expired token"}), 400

    # Validate user
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    new_password = data.get("new_password")
    if not new_password:
        return jsonify({"error": "New password is required."}), 400

    # Update the user's password
    user.password = new_password  # Hashing is handled by the setter
    db.session.commit()

    return jsonify({"message": "Password has been reset successfully."}), 200


@app.route('/api/user', methods=['GET'])
@jwt_required()
def get_user():
    """
    Validate token and return user details.
    """
    try:
        current_user_id = get_jwt_identity()  # Extract user ID from the token
        user = User.query.get(current_user_id)

        if not user:
            return jsonify({"error": "User not found"}), 404

        return jsonify({
            "id": user.id,
            "username": user.username,
            "email": user.email
        }), 200

    except Exception as e:
        print(f"Error fetching user: {str(e)}")
        return jsonify({"error": "Failed to fetch user details."}), 500






#---------------------------------------------------------------------

class Package(db.Model):
    __tablename__ = "packages"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    image_url = db.Column(db.String(255), nullable=True)
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=db.func.now(), nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "amount": self.amount,
            "image_url": self.image_url,
            "description": self.description,
            "created_at": self.created_at.strftime("%Y-%m-%d %H:%M:%S"),
        }

@app.post('/api/packages')
def create_package():
    """
    Create a new package with an image URL.
    """
    data = request.get_json()
    title = data.get("title")
    amount = data.get("amount")
    description = data.get("description")
    image_url = data.get("image_url", "").strip()

    # Validate required fields
    if not title or not amount:
        return jsonify({"error": "Title and amount are required."}), 400

    # Validate image URL
    if image_url and not is_valid_url(image_url):
        return jsonify({"error": "Invalid image URL."}), 400

    # Create new package
    try:
        new_package = Package(
            title=title,
            amount=float(amount),
            description=description,
            image_url=image_url,
        )
        db.session.add(new_package)
        db.session.commit()
    except Exception as e:
        return jsonify({"error": "Failed to create package."}), 500

    return jsonify({"message": "Package created successfully!", "package": new_package.to_dict()}), 201
@app.put('/api/packages/<int:package_id>')
def update_package(package_id):
    """
    Update a package by ID.
    """
    package = Package.query.get(package_id)
    if not package:
        return jsonify({"error": "Package not found."}), 404

    # Parse incoming JSON data
    data = request.get_json()

    # Update fields
    package.title = data.get("title", package.title)
    package.amount = float(data.get("amount", package.amount))
    package.description = data.get("description", package.description)
    package.image_url = data.get("image_url", package.image_url)  # Update image URL if provided

    db.session.commit()
    return jsonify({"message": "Package updated successfully!", "package": package.to_dict()}), 200

@app.delete('/api/packages/<int:package_id>')
def delete_package(package_id):
    """
    Delete a package by ID.
    """
    package = Package.query.get(package_id)
    if not package:
        return jsonify({"error": "Package not found."}), 404

    # Only delete local file paths, not external URLs
    if package.image_url and package.image_url.startswith("uploads/"):
        if os.path.exists(package.image_url):
            os.remove(package.image_url)

    db.session.delete(package)
    db.session.commit()

    return jsonify({"message": "Package deleted successfully!"}), 200
def is_valid_url(url):
    return re.match(r'^https?://', url) is not None
@app.get('/api/packages')
def get_packages():
    """
    Retrieve all packages.
    """
    try:
        packages = Package.query.all()
        return jsonify([package.to_dict() for package in packages]), 200
    except Exception as e:
        print(f"ERROR: Failed to fetch packages - {e}")
        return jsonify({"error": "Failed to fetch packages."}), 500

from datetime import datetime, timedelta

@app.delete('/api/cleanup_old_records')
def delete_old_records():
    """
    Delete one-time cleanings and recurring paid records older than 90 days.
    """
    try:
        # Define the cutoff date
        cutoff_date = datetime.utcnow() - timedelta(days=90)
        print(f"Cutoff date for deletion: {cutoff_date}")

        # Track deleted records count
        recurring_paid_deleted_count = 0

        # Delete old one-time cleanings
        old_one_time_cleanings = OneTimeCleaning.query.filter(OneTimeCleaning.date_time < cutoff_date).all()
        print(f"Found {len(old_one_time_cleanings)} old one-time cleanings")
        for cleaning in old_one_time_cleanings:
            db.session.delete(cleaning)
        print(f"Deleted {len(old_one_time_cleanings)} one-time cleanings")

        # Delete old recurring paid records
        old_recurring_paid = RecurringPaid.query.all()
        print(f"Found {len(old_recurring_paid)} recurring paid records")

        for record in old_recurring_paid:
            if record.dates_related:
                print(f"Processing recurring paid record ID {record.id}, dates_related: {record.dates_related}")
                try:
                    # Handle multiple dates in dates_related field
                    dates = record.dates_related.split(",")
                    for date_str in dates:
                        date_str = date_str.strip()
                        try:
                            related_date = datetime.strptime(date_str, "%Y-%m-%dT%H:%M")
                            print(f"Parsed related date: {related_date}")

                            if related_date < cutoff_date:
                                db.session.delete(record)
                                recurring_paid_deleted_count += 1
                                print(f"Deleted recurring paid record ID {record.id}")
                                break  # Stop once we find one valid date
                        except ValueError:
                            print(f"Skipping date {date_str} in record {record.id}, invalid date format")

                except ValueError:
                    print(f"Skipping record {record.id}, invalid dates_related format: {record.dates_related}")

        # Commit the deletions
        db.session.commit()
        print(f"Total recurring paid records deleted: {recurring_paid_deleted_count}")

        return jsonify({
            "message": "Old records deleted successfully.",
            "one_time_cleanings_deleted": len(old_one_time_cleanings),
            "recurring_paid_deleted": recurring_paid_deleted_count
        }), 200

    except Exception as e:
        print(f"Error deleting old records: {e}")
        db.session.rollback()
        return jsonify({"error": "Failed to delete old records."}), 500


def format_date(date_obj):
    if date_obj:
        return date_obj.strftime("%A, %B %d, %Y %I:%M %p")
    return None

@app.get('/api/old_records')
def get_old_records():
    """
    Fetch one-time cleanings and recurring paid records older than 90 days.
    """
    try:
        ninety_days_ago = datetime.utcnow() - timedelta(days=90)
        print(f"Cutoff date for old records: {ninety_days_ago}")

        # Fetch one-time cleanings older than 90 days
        old_one_time_cleanings = OneTimeCleaning.query.filter(OneTimeCleaning.date_time < ninety_days_ago).all()
        print(f"Found {len(old_one_time_cleanings)} old one-time cleanings")

        # Fetch recurring paid records where the related date is older than 90 days
        old_recurring_paid = RecurringPaid.query.filter(
            RecurringPaid.dates_related.isnot(None)
        ).all()
        print(f"Found {len(old_recurring_paid)} recurring paid records with dates_related")

        filtered_recurring_paid = []
        for record in old_recurring_paid:
            if record.dates_related:
                print(f"Processing recurring paid record ID {record.id}, dates_related: {record.dates_related}")
                try:
                    # Split the date range by comma if it exists
                    dates = record.dates_related.split(",")
                    for date_str in dates:
                        # Clean up any extra spaces and parse the date
                        date_str = date_str.strip()
                        try:
                            related_date = datetime.strptime(date_str, "%Y-%m-%dT%H:%M")
                            print(f"Parsed related date: {related_date}")

                            if related_date < ninety_days_ago:
                                filtered_recurring_paid.append(record)
                                print(f"Record ID {record.id} is older than 90 days and is added.")
                                break  # Stop once we find one valid date

                        except ValueError:
                            print(f"Skipping date {date_str} in record {record.id}, invalid date format")

                except ValueError:
                    print(f"Skipping record {record.id}, invalid date format: {record.dates_related}")

        # Format response
        old_records = [
            {
                "id": record.id,
                "name": record.inquiry.name,
                "submitted_at": format_date(record.date_time),
                "type": "One-time Cleaning"
            } for record in old_one_time_cleanings
        ] + [
            {
                "id": record.id,
                "name": record.recurring_payment.inquiry.name,
                "submitted_at": format_date(record.submitted_at),
                "dates_related": [format_date(datetime.strptime(date_str.strip(), "%Y-%m-%dT%H:%M")) for date_str in record.dates_related.split(",")],
                "type": "Recurring Paid"
            } for record in filtered_recurring_paid
        ]

        print(f"Total records to return: {len(old_records)}")
        return jsonify(old_records), 200

    except Exception as e:
        print(f"Error fetching old records: {e}")
        return jsonify({"error": "Failed to fetch old records."}), 500


# Run the app
if __name__ == "__main__":
    app.run(debug=True)
