from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import json
import datetime
import jwt
import os
from dotenv import load_dotenv
from passlib.hash import pbkdf2_sha256 
app = Flask(__name__)
load_dotenv()
SECRET_KEY = "secret_key" # os.getenv("APP_SECRET_KEY")
app.secret_key = "secret" # os.getenv("SECRET_KEY")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///TravelPlannerDB.sqlite3" # os.getenv("DATABASE_URI")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)



class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(10), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    token= db.Column(db.String(500))

    def __init__(self, name, email, role, password, token):
        self.name = name
        self.email = email
        self.role = role
        self.password = password
        self.token = token


class Package(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    rating = db.Column(db.Float, default=0.0)
    pincode = db.Column(db.Integer, nullable=False)
    country = db.Column(db.String(255), nullable=False)

    def __init__(self, name, description, rating, pincode, country):
        self.name = name
        self.description = description
        self.rating = rating
        self.pincode = pincode
        self.country = country

class Itinerary(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    package_id = db.Column(db.Integer, db.ForeignKey('package.id'))
    date = db.Column(db.String(255))
    activity = db.Column(db.String(255)) 
    expense = db.Column(db.Float)

    def __init__(self, package_id, date, activity, expense):
        self.package_id = package_id
        self.date = date
        self.activity = activity
        self.expense = expense


with app.app_context():
    db.create_all()


@app.route('/')
def welcome():
    return jsonify({'message': 'Welcome to Wanderlust Travel Planner'})

@app.route("/login", methods=['POST'])
def loginUser():
    data = request.get_json()
    allUsers = Users.query.all()
    for user in allUsers:
        if(user.email == data['email'] and pbkdf2_sha256.verify(data['password'], user.password)):
            token = jwt.encode({"user": {'email': user.email, 'role': user.role}}, SECRET_KEY, algorithm='HS256')
            user.token = token
            db.session.commit()
            return jsonify({'issue': False, 'token': token,  'message': "login success"})
    
    return jsonify({'issue': True, 'message': 'Invalid user data'})


@app.route('/register', methods=['POST'])
def registerUser():
    try:
        data = request.get_json()
        users = Users.query.all()
        
        for user in users:
            if(user.email == data['email']):
                return jsonify({'issue': True,  'message': "email is already present in database"})

        hashed = pbkdf2_sha256.using(rounds=10, salt_size=16).hash(data['password'])
        new_user = Users(name=data['name'], email=data['email'], password=hashed, role=data['role'], token=data['token'])
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'issue': False, 'message': 'register success'})
    except Exception as e:
        return jsonify({'issue': True, 'message':str(e)})


@app.route("/profile", methods=['POST'])
def udpateProfile():
    try:
        token = request.headers.get('Authorization')
        decoded_token = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        user_data = decoded_token['user']
        user = Users.query.filter_by(email=user_data['email']).first()
        data = request.get_json()
        if 'name' in data:
            user.name = data['name']
        if 'address' in data:
            user.address = data['address']
        if 'pincode' in data:
            user.pincode = data['pincode']

        db.session.commit()
        return jsonify({'issue': False,'message': f'user data updated successfully!'})
    except Exception as e:
        return jsonify({'issue': True, 'message': str(e)})


@app.route("/package", methods=['POST', "GET"])
def postPackage():
    try:
        if(request.method == 'POST'):
            dest = request.get_json()
            token = request.headers.get('Authorization')
            decoded_token = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            user_data = decoded_token['user']

            if(user_data['role'] == 'admin'):
                new_Package = Package(name=dest['name'], description=dest['description'], rating=dest['rating'], pincode=dest['pincode'], country=dest['country'])
                db.session.add(new_Package)
                db.session.commit()
                return jsonify({'issue': False, 'message': "Package added!"})
            else:
                return jsonify({'issue': True, 'message': 'Access Denied!'})
            
        
        # get request
        allDest = Package.query.all()
        allDest_list = []
        for single in allDest:
            single_info = {
            

                  "id" : single.id,
                "name" : single.name,
                "description" : single.description,
                "rating" : single.rating,
                "pincode" : single.pincode,
                "country" : single.country
               
            }
            allDest_list.append(single_info)

        return jsonify({'issue': False, 'message': "All Package", "Package": allDest_list})
        
    except Exception as e:
        return jsonify({'issue': True, 'message': str(e)})

@app.route('/package/<int:id>', methods=['GET', "DELETE", "PATCH", "PUT"])
def singlePackage(id):
    try:
        single_dest = Package.query.filter_by(id=id).first()

        if(request.method == 'GET'):
            single = {
                'id': single_dest.id,
                'name': single_dest.name,
                'description': single_dest.description,
                "rating": single_dest.rating,
                'pincode': single_dest.pincode,
                'country': single_dest.country
            }
                
            return jsonify({'issue': False, 'message': f"Package id {id}.", "Package": single})

        token = request.headers.get('Authorization')
        decoded_token = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        user_data = decoded_token['user']

        if(user_data['role'] == 'admin'):
            if(request.method == "DELETE"):
                db.session.delete(single_dest)
                db.session.commit()
                return jsonify({'isssue': False, 'message': f'Package id {id} deleted!' })
            
            dest = request.get_json()
            if 'name' in dest:
                single_dest.name = dest['name']
            elif 'description' in dest:
                single_dest.description = dest['description']
            elif 'rating' in dest:
                single_dest.rating = dest['rating']
            elif 'pincode' in dest:
                single_dest.pincode = dest['pincode']
            elif 'country' in dest:
                single_dest.country = dest['country']

            db.session.commit()
            return jsonify({'issue': False, 'message': f"Package id {id} updated!"})
        else:
            return jsonify({'issue': True, 'message': 'Access Denied!'})

    except Exception as e:
        return jsonify({'issue': True, "message": str(e)})


@app.route('/plans', methods=['GET', 'POST'])
def postPlans():
    try:
        if(request.method == 'POST'):
            dest = request.get_json()
            token = request.headers.get('Authorization')
            decoded_token = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            user_data = decoded_token['user']

            if(user_data['role'] == 'admin'):
                new_plan = Itinerary(package_id=dest['package_id'], date=dest['date'], activity=dest['activity'], expense=dest['expense'])
                db.session.add(new_plan)
                db.session.commit()
                return jsonify({'issue': False, 'message': "Plan added!"})
            else:
                return jsonify({'issue': True, 'message': 'Access Denied!'})
            
        
        # get request
        allDest = Itinerary.query.all()
        allDest_list = []
        for single in allDest:
            
            single_info = {
                "id" : single.id,
                "package_id" : single.package_id,
                "date" : single.date,
                "activity" : single.activity,
                "expense" : single.expense
               
            }
            allDest_list.append(single_info)

        return jsonify({'issue': False, 'message': "All Plan", "Plan": allDest_list})
        
    except Exception as e:
        return jsonify({'issue': True, 'message': str(e)})

 
@app.route('/plans/<int:id>', methods=['GET', 'PUT', "DELETE", 'PATCH'])
def singlePlans(id):
    try:
        plan = Itinerary.query.filter_by(id=id).first()
        if not plan:
            return jsonify({'issue': True, 'message': f"No plan found with id {id}"})

        if(request.method == 'GET'):
            single_plan = {
                'id': plan.id,
                'package_id': plan.package_id,
                'activity': plan.activity,
                'date': plan.date,
                'expense': plan.expense
            }
            return jsonify({'issue': False, 'message': f"{id} plan", 'plan': single_plan})

        token = request.headers.get("Authorization")
        decode_token = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        user_data = decode_token['user']

        if(user_data['role'] == 'admin'):
            if(request.method == 'DELETE'):
                db.session.delete(plan)
                db.session.commit()
                return jsonify({'issue': False, 'message': f'{id} id deleted successfully!'})
            
            data = request.get_json()
            if 'package_id' in data:
                plan.package_id = data['package_id']
            elif 'date' in data:
                plan.date = data['date']
            elif 'activity' in data:
                plan.acitivity = data['activity']
            elif 'expense' in data:
                plan.expense = data['expense']
            db.session.commit()
            return jsonify({'issue': False, 'message': f"{id} id updated!"})
        else:
            return jsonify({'issue': True, 'message': 'Access Denied!'})
    except Exception as e:
        return jsonify({'issue': True, 'message': str(e)})


@app.route("/package/<int:packageId>/plans", methods=["GET"])
def getPackagePlan(packageId):
    try:
        all_plans = Itinerary.query.filter_by(package_id=packageId)

        packages = []
        
        for plan in all_plans:
            single_plan = {
                'package_id': plan.package_id,
                'date': plan.date,
                'activity': plan.activity,
                'expense': plan.expense
            }
            packages.append(single_plan)
        return jsonify({'issue': False, 'message': f"All plans of package id {packageId}", 'plan': packages})

    except Exception as e:
        return jsonify({'issue': True, 'message': str(e)})
    

if __name__ == '__main__':
    app.run(debug=False)