import uuid
from model  import *
from flask import Flask,request ,redirect, url_for
from flask_cors import CORS, cross_origin
from flask import jsonify
import json
from flask_mongoengine import MongoEngine
from mongoengine.connection import disconnect
from flask_jwt_extended import JWTManager
from flask_jwt_extended import (create_access_token, create_refresh_token,verify_jwt_in_request, jwt_required,jwt_optional, jwt_refresh_token_required, get_jwt_identity, get_raw_jwt,get_jwt_claims)
from passlib.hash import pbkdf2_sha256 as sha256
from waitress import serve
app = Flask(__name__)

app.config['CORS_HEADERS'] = 'Content-Type'
app.config['JWT_SECRET_KEY'] = 'nevergiveup'
app.config['JWT_ERROR_MESSAGE_KEY'] = 'status'  
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']

jwt = JWTManager(app)
#CORS(app,resources={r"*": {"origins": "http://localhost:4200"}})
CORS(app, resources={r"*": {"origins": "http://localhost:4200"}})

@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    connect(alias='b4xab7lqny8ghgn')
    jti = decrypted_token['jti']
    token=TokenBlacklist()
    if token.validate_token(token=jti):
        return jsonify({'code': 401,'status': 'Invalid'})

@jwt.user_claims_loader
def add_claims_to_access_token(identity):
    user=User.objects(email=identity).first()
    return {
        'user_id':str(user.id),
        'username': user.user_name,
        'name' : user.first_name +' '+user.last_name,
    }

@jwt.expired_token_loader
def expired_token_callback(expired_token):
    #return redirect(url_for('refresh_token'))
    return jsonify({'code': 401,'status': 'Invalid'})
    
@jwt_refresh_token_required
@app.route('/auth',methods = ['GET'])
@cross_origin()
def refresh_token():
    try:
        current_user = get_jwt_identity()
        access_token = create_access_token(identity = current_user)
        return jsonify({'code':200,'status':'Success','access_token': access_token})
    except:
        return jsonify({'code':401,'status':'Invalid'})

'''Auth services'''
@app.route('/auth/signup/',methods = ['POST'])
def signup():
    requestbody =json.loads(request.data)
    if(len(requestbody['password']) < 8):
        return jsonify({'code': 400,'status': 'Password must be minimun 8 characters'})
    requestbody['password']= sha256.hash(requestbody['password'])   
    try:
        connect(alias='b4xab7lqny8ghgn')
        user=User()
        is_valid=user.validate_record(requestbody['username'],requestbody['email'],requestbody['password'],requestbody['fname'],requestbody['lname'])
        if(is_valid == True):
            user=User(password=requestbody['password'],user_name=requestbody['username'],email=requestbody['email'],first_name=requestbody['fname'],last_name=requestbody['lname'])
            user.save()
            access_token = create_access_token(identity = user.email)
            refresh_token = create_refresh_token(identity = user.email)
            return jsonify({'code': 200,'status': 'Success','access-token':access_token,'refresh-token':refresh_token})
        else:
            error = is_valid
            return jsonify({'code': 400,'status': error})
            disconnect(alias='b4xab7lqny8ghgn')
    except Exception as e:
        print(e)
        return jsonify({'code': 500,'status': 'Internal Server Error'})
        disconnect(alias='b4xab7lqny8ghgn')

          
@app.route('/validateusername',methods = ['POST'])
@cross_origin()
def validate_username():
    requestbody =json.loads(request.data)
    try:
        connect(alias='b4xab7lqny8ghgn')
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
        connect(alias='b4xab7lqny8ghgn')
        user=User()
        is_valid = user.validate_email(requestbody['email'])
        if(is_valid == True):
            return jsonify({'code': 200,'status': 'Success'})
        return jsonify({'code': 400,'status': is_valid})
    except Exception as e:
        print(e)
        return jsonify({'code': 500,'status': 'Internal Server Error'})
    
@app.route('/auth/validate/',methods = ['GET'])
@jwt_optional
@cross_origin()
def validate_session():
    claims = get_jwt_claims()
    if claims:
        try:
            connect(alias='b4xab7lqny8ghgn')
            user=User()
            is_valid = user.check_user_session(claims)
            if is_valid:
                return jsonify({'code': 200,'status': 'Valid'}),200
            return jsonify({'code': 400,'status': 'Invalid'}),400
        except Exception as e:
            print(e)
            return jsonify({'code': 500,'status': 'Internal Server Error'})
    return jsonify({'code': 400,'status': 'Invalid'}),400
    

@app.route('/auth/signin/',methods = ['POST'])
@cross_origin()
def signin():
    requestbody =json.loads(request.data)
    try:
        connect(alias='b4xab7lqny8ghgn')
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
    

@app.route('/auth/signout',methods = ['GET'])
@jwt_required
@cross_origin()
def signout():
    connect(alias='b4xab7lqny8ghgn')
    jti = get_raw_jwt()['jti']
    blacklist =TokenBlacklist()
    blacklist.add_to_blacklist(jti)
    return jsonify({'code': 200,'status': 'Successfully logged out'})

@app.route('/auth/forgot',methods = ['POST'])
@cross_origin()
def forgot_password():
    requestbody =json.loads(request.data)
    if requestbody:
        connect(alias='b4xab7lqny8ghgn')
        user= User()
        if(user.forgot_password_otp(requestbody)):
            return jsonify({'code': 200,'status': 'Success'})
        return jsonify({'code': 400,'status': 'Something went wrong.'})
    return jsonify({'code': 400,'status': 'Something went wrong.'})
    
@app.route('/auth/guard/',methods = ['POST'])
@cross_origin()
def auth_guard():
    requestbody =json.loads(request.data)
    print(requestbody,"requestbody")
    if requestbody:
        connect(alias='b4xab7lqny8ghgn')
        if(1==1):
            return jsonify({'code': 200,'status': 'Success'})
        return jsonify({'code': 400,'status': 'Something went wrong.'})
    return jsonify({'code': 400,'status': 'Something went wrong.'})
@app.route('/auth/reset',methods = ['POST'])
@cross_origin()
def reset_password():
    requestbody =json.loads(request.data)
    if requestbody:
        connect(alias='b4xab7lqny8ghgn')
        user= User()
        if(user.reset_password(requestbody)):
            return jsonify({'code': 200,'status': 'Success'})
        return jsonify({'code': 400,'status': 'Something went wrong.'})
    return jsonify({'code': 400,'status': 'Something went wrong.'})

'''Post services'''
@app.route('/post/',methods = ['POST'])
@jwt_required
@cross_origin()
def save_post():
    requestbody =json.loads(request.data)
    print(requestbody,"requestbody");
    try:
        claims = get_jwt_claims()
        connect(alias='b4xab7lqny8ghgn')
        post=Post()
        is_valid = post.validate_post(requestbody,claims)
        if is_valid:
            return jsonify({'code': 200,'status': 'Saved successfully','id' :is_valid})
        return jsonify({'code': 400,'status': 'Something went wrong.'})
    except Exception as e:
        print(e,"posttt")
        return jsonify({'code': 500,'status': 'Internal Server Error'})
    
@app.route('/post/all/',methods = ['GET'])
@jwt_required
@cross_origin()
def view_all_post():
    try:
        claims = get_jwt_claims()
        connect('around')
        post=Post()
        is_valid = post.view_all_post(claims)
        if is_valid:
            return jsonify({'code': 200,'status': 'Success','posts' :is_valid})
        return jsonify({'code': 400,'status': 'Something went wrong.'})
    except Exception as e:
        return jsonify({'code': 500,'status': 'Internal Server Error'})
    
@app.route('/post/<post_id>',methods = ['GET'])
@jwt_optional
@cross_origin()
def view_post(post_id):
    try:
        claims = get_jwt_claims()
        connect(alias='b4xab7lqny8ghgn')
        post=Post()
        is_valid = post.view_post(post_id,claims)
        if is_valid:
            return jsonify({'code': 200,'status': 'Success','data' :is_valid})
        return jsonify({'code': 400,'status': 'Something went wrong.'})
    except Exception as e:
        print(e,"except")
        return jsonify({'code': 500,'status': 'Internal Server Error'})
    
    
@app.route('/delete',methods = ['POST'])
@jwt_required
@cross_origin()
def delete_post():
    try:
        post_id = request.args.get('post',False)
        if post_id:
            claims = get_jwt_claims()
            connect(alias='b4xab7lqny8ghgn')
            post=Post()
            is_valid = post.delete_post(post_id,claims)
            if is_valid:
                return jsonify({'code': 200,'status': 'Success'})
        return jsonify({'code': 400,'status': 'Something went wrong.'})
    except Exception as e:
        print(e)
        return jsonify({'code': 500,'status': 'Internal Server Error'})
    
'''search services'''
@app.route('/delete',methods = ['POST'])
@jwt_required
@cross_origin()
def search():
    try:
        search = request.args.get('value',False)
        object =  request.args.get('search',False)
        if search and object:
            claims = get_jwt_claims()
            connect(alias='b4xab7lqny8ghgn')
            post=Post()
            is_valid = post.search_around(request.args,claims)
            if is_valid:
                return jsonify({'code': 200,'status': 'Success','data':is_valid})
        return jsonify({'code': 400,'status': 'Something went wrong.'})
    except Exception as e:
        print(e)
        return jsonify({'code': 500,'status': 'Internal Server Error'})    
        
    
    
if __name__ == '__main__':
    db = MongoEngine(app)
    serve(app)
    
    
    
