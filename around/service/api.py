import uuid
from models.model  import *
from flask import Flask,request ,redirect, url_for
from flask_cors import CORS, cross_origin
from flask import jsonify
import json
from mongoengine import *
from flask_jwt_extended import (create_access_token, create_refresh_token, jwt_required, jwt_refresh_token_required, get_jwt_identity, get_raw_jwt)
from passlib.hash import pbkdf2_sha256 as sha256
app = Flask(__name__)
cors = CORS(app)
from flask_jwt_extended import JWTManager
app.config['JWT_SECRET_KEY'] = 'nevergiveup'
app.config['JWT_ERROR_MESSAGE_KEY'] = 'status'
jwt = JWTManager(app)
app.config['CORS_HEADERS'] = 'Content-Type'

@jwt.user_claims_loader
def add_claims_to_access_token(identity):
    user=User.objects(email=identity).first()
    return {
        'username': user.user_name,
        'name' : user.first_name +' '+user.last_name,
    }

@jwt.expired_token_loader
def expired_token_callback(expired_token):
    #return redirect(url_for('refresh_token'))
    return jsonify({'code': 401,'status': 'Expired'})
    
@jwt_refresh_token_required
@app.route('/auth',methods = ['GET'])
@cross_origin()
def refresh_token():
    try:
        current_user = get_jwt_identity()
        access_token = create_access_token(identity = current_user)
        return jsonify({'code':200,'status':'Success','access_token': access_token})
    except:
        return jsonify({'code':401,'status':'Expired'})


@app.route('/signup',methods = ['POST'])
@cross_origin()
def signup():
    requestbody =json.loads(request.data)
    if(len(requestbody['password']) < 8):
        return jsonify({'code': 400,'status': 'Password should be min 8 characters'})
    requestbody['password']= sha256.hash(requestbody['password'])   
    try:
        connect('around')
        user=User()
        is_valid=user.validate_record(requestbody['username'],requestbody['email'],requestbody['password'],requestbody['fname'],requestbody['lname'])
        if(is_valid == True):
            user=User(password=requestbody['password'],user_name=requestbody['username'],email=requestbody['email'],first_name=requestbody['fname'],last_name=requestbody['lname'],location = requestbody.get('location',[0,0]))
            user.save()
            access_token = create_access_token(identity = user.email)
            refresh_token = create_refresh_token(identity = user.email)
            return jsonify({'code': 200,'status': 'Success','access-token':access_token,'refresh-token':refresh_token})
        else:
            error = is_valid
            return jsonify({'code': 400,'status': error}) 
    except Exception as e:
        print(e)
        return jsonify({'code': 500,'status': 'Internal Server Error'})
    
@app.route('/validateusername',methods = ['POST'])
@cross_origin()
def validate_username():
    requestbody =json.loads(request.data)
    try:
        connect('around')
        user=User()
        is_valid = user.validate_username(requestbody['username'])
        if(is_valid == True):
            return jsonify({'code': 200,'status': 'Success'})
        return jsonify({'code': 400,'status': is_valid})
    except Exception as e:
        print(e)
        return jsonify({'code': 500,'status': 'Internal Server Error'}) 
    
@app.route('/validateemail',methods = ['POST'])
@cross_origin()
def validate_email():
    requestbody =json.loads(request.data)
    try:
        connect('around')
        user=User()
        is_valid = user.validate_email(requestbody['email'])
        if(is_valid == True):
            return jsonify({'code': 200,'status': 'Success'})
        return jsonify({'code': 400,'status': is_valid})
    except Exception as e:
        print(e)
        return jsonify({'code': 500,'status': 'Internal Server Error'})
    
    

@app.route('/signin',methods = ['POST'])
@cross_origin()
def signin():
    requestbody =json.loads(request.data)
    print(requestbody['password'])
    try:
        connect('around')
        user=User()
        is_valid = user.validate_sign_in(requestbody['email'],requestbody['password'])
        if is_valid:
            access_token = create_access_token(identity = is_valid)
            refresh_token = create_refresh_token(identity = is_valid)
            return jsonify({'code': 200,'status': 'Success','access-token':access_token,'refresh-token':refresh_token})
        return jsonify({'code': 400,'status': 'Email or Password is incorrect.'})
    except Exception as e:
        print(e)
        return jsonify({'code': 500,'status': 'Internal Server Error'}) 
    
if __name__ == '__main__':
    app.debug = True
    app.run(debug = True)
