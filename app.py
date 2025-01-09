import hashlib
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity

# Initialize Flask App
app = Flask(__name__)

# Configuration for Flask
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///exams.db'
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'  # Change to a secure key
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # To suppress a warning

# Initialize extensions
db = SQLAlchemy(app)
jwt = JWTManager(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False)  # 'student' or 'admin'

class Exam(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    questions = db.relationship('Question', backref='exam', lazy=True)

class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    exam_id = db.Column(db.Integer, db.ForeignKey('exam.id'), nullable=False)
    text = db.Column(db.String(200), nullable=False)
    options = db.relationship('Option', backref='question', lazy=True)
    correct_answer = db.Column(db.String(200), nullable=False)

class Option(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'), nullable=False)
    text = db.Column(db.String(100), nullable=False)

class Result(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    exam_id = db.Column(db.Integer, db.ForeignKey('exam.id'), nullable=False)
    score = db.Column(db.Integer, nullable=False)
    remarks = db.Column(db.String(50), nullable=False)

# Routes
@app.route('/')
def home():
    return "Welcome to the Exam Admin App"

# User Registration Route
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    role = data.get('role')
    
    # Password hashing
    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    # Create new user
    new_user = User(username=username, password=hashed_password, role=role)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User registered successfully"}), 201

# User Login Route
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # Get user from database
    user = User.query.filter_by(username=username).first()
    if user and user.password == hashlib.sha256(password.encode()).hexdigest():
        access_token = create_access_token(identity=user.id)
        return jsonify({"access_token": access_token}), 200
    
    return jsonify({"message": "Invalid credentials"}), 401

# Admin route to create an Exam
@app.route('/exam', methods=['POST'])
@jwt_required()
def create_exam():
    current_user = get_jwt_identity()
    user = User.query.get(current_user)
    
    if user.role != 'admin':
        return jsonify({"message": "Only admin can create exams"}), 403

    data = request.get_json()
    title = data.get('title')

    new_exam = Exam(title=title)
    db.session.add(new_exam)
    db.session.commit()

    return jsonify({"message": "Exam created successfully", "exam_id": new_exam.id}), 201

# Admin route to add a Question to an Exam
@app.route('/exam/<int:exam_id>/question', methods=['POST'])
@jwt_required()
def add_question(exam_id):
    current_user = get_jwt_identity()
    user = User.query.get(current_user)

    if user.role != 'admin':
        return jsonify({"message": "Only admin can add questions"}), 403

    data = request.get_json()
    text = data.get('text')
    correct_answer = data.get('correct_answer')
    options = data.get('options')

    new_question = Question(exam_id=exam_id, text=text, correct_answer=correct_answer)
    db.session.add(new_question)
    db.session.commit()

    # Add options
    for option_text in options:
        option = Option(question_id=new_question.id, text=option_text)
        db.session.add(option)
    db.session.commit()

    return jsonify({"message": "Question added successfully", "question_id": new_question.id}), 201

# Route to take an exam (students)
@app.route('/exam/<int:exam_id>/attempt', methods=['POST'])
@jwt_required()
def attempt_exam(exam_id):
    current_user = get_jwt_identity()
    user = User.query.get(current_user)

    if user.role != 'student':
        return jsonify({"message": "Only students can take exams"}), 403

    data = request.get_json()
    answers = data.get('answers')  # A dictionary {question_id: answer}

    exam = Exam.query.get(exam_id)
    if not exam:
        return jsonify({"message": "Exam not found"}), 404

    correct_answers = 0
    total_questions = 0

    for question in exam.questions:
        total_questions += 1
        if answers.get(str(question.id)) == question.correct_answer:
            correct_answers += 1

    # Calculate score and remarks
    score = (correct_answers / total_questions) * 100
    remarks = "Pass" if score >= 50 else "Fail"

    # Store result
    result = Result(student_id=current_user, exam_id=exam_id, score=score, remarks=remarks)
    db.session.add(result)
    db.session.commit()

    return jsonify({"score": score, "remarks": remarks}), 200

# Initialize the app context for creating tables
if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Create the database tables
    app.run(debug=True)
