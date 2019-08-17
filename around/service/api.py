import uuid
from model  import *
from flask import Flask,request ,redirect, url_for
from flask_cors import CORS, cross_origin
from flask import jsonify
import json
from mongoengine import *
from flask_jwt_extended import (create_access_token, create_refresh_token, jwt_required, jwt_refresh_token_required, get_jwt_identity, get_raw_jwt,get_jwt_claims)
from passlib.hash import pbkdf2_sha256 as sha256
app = Flask(__name__)
cors = CORS(app)
from flask_jwt_extended import JWTManager
app.config['JWT_SECRET_KEY'] = 'nevergiveup'
app.config['JWT_ERROR_MESSAGE_KEY'] = 'status'
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']
jwt = JWTManager(app)
app.config['CORS_HEADERS'] = 'Content-Type'

@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    connect('around')
    jti = decrypted_token['jti']
    token=TokenBlacklist()
    if token.validate_token(token=jti):
        return jsonify({'code': 401,'status': 'Token Expired'})
    

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
    return jsonify({'code': 401,'status': 'Token Expired'})
    
@jwt_refresh_token_required
@app.route('/auth',methods = ['GET'])
@cross_origin()
def refresh_token():
    try:
        current_user = get_jwt_identity()
        access_token = create_access_token(identity = current_user)
        return jsonify({'code':200,'status':'Success','access_token': access_token})
    except:
        return jsonify({'code':401,'status':'Token Expired'})


@app.route('/auth/signup',methods = ['POST'])
@cross_origin()
def signup():
    requestbody =json.loads(request.data)
    if(len(requestbody['password']) < 8):
        return jsonify({'code': 400,'status': 'Password must be minimun 8 characters'})
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
    
    

@app.route('/auth/signin',methods = ['POST'])
@cross_origin()
def signin():
    requestbody =json.loads(request.data)
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
    

@app.route('/auth/signout',methods = ['GET'])
@jwt_required
@cross_origin()
def signout():
    connect('around')
    jti = get_raw_jwt()['jti']
    blacklist =TokenBlacklist()
    blacklist.add_to_blacklist(jti)
    return jsonify({'code': 200,'status': 'Successfully logged out'})

@app.route('/post',methods = ['POST'])
@jwt_required
@cross_origin()
def save_post():
    requestbody =json.loads(request.data)
    try:
        claims = get_jwt_claims()
        connect('around')
        post=Post()
        is_valid = post.validate_post(requestbody,claims)
        if is_valid:
            return jsonify({'code': 200,'status': 'Saved successfully','id' :is_valid})
        return jsonify({'code': 400,'status': 'Something went wrong.'})
    except Exception as e:
        print(e)
        return jsonify({'code': 500,'status': 'Internal Server Error'})
    
@app.route('/post/<post_id>',methods = ['GET'])
@cross_origin()
def view_post(post_id):
    try:
        claims = get_jwt_claims()
        connect('around')
        post=Post()
        is_valid = post.view_post(post_id,claims)
        if is_valid:
            return jsonify({'code': 200,'status': 'Success','data' :is_valid})
        return jsonify({'code': 400,'status': 'Something went wrong.'})
    except Exception as e:
        print(e)
        return jsonify({'code': 500,'status': 'Internal Server Error'})
    
    
@app.route('/delete',methods = ['POST'])
@jwt_required
@cross_origin()
def delete_post():
    try:
        post_id = request.args.get('post',False)
        print(post_id)
        if post_id:
            claims = get_jwt_claims()
            connect('around')
            post=Post()
            is_valid = post.delete_post(post_id,claims)
            if is_valid:
                return jsonify({'code': 200,'status': 'Success'})
        return jsonify({'code': 400,'status': 'Something went wrong.'})
    except Exception as e:
        print(e)
        return jsonify({'code': 500,'status': 'Internal Server Error'})
    
    
if __name__ == '__main__':
    app.debug = True
    app.run(debug = True)
    
    
