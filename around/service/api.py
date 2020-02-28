import uuid
from model  import *
from flask import Flask,request ,redirect, url_for
from flask_cors import CORS, cross_origin
from flask import jsonify
import json
import traceback
from flask_mongoengine import MongoEngine
from mongoengine.connection import disconnect
from flask_jwt_extended import JWTManager
from flask_jwt_extended import (create_access_token, create_refresh_token,verify_jwt_in_request, jwt_required,jwt_optional, jwt_refresh_token_required, get_jwt_identity, get_raw_jwt,get_jwt_claims)
from passlib.hash import pbkdf2_sha256 as sha256
from waitress import serve
app = Flask(__name__)
#hari added
app.config['CORS_HEADERS'] = 'Content-Type'
app.config['JWT_SECRET_KEY'] = 'nevergiveup'
app.config['JWT_ERROR_MESSAGE_KEY'] = 'status'  
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

jwt = JWTManager(app)
#CORS(app,resources={r"*": {"origins": "http://localhost:4200"}})
CORS(app, resources={r"*": {"origins": "http://localhost:4200"}})

@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    connect(alias='around')
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
        return jsonify({'code': 400,'status': 'Password must be minimum 8 characters'})
    requestbody['password']= sha256.hash(requestbody['password'])   
    try:
        connect(alias='around')
        user=User()
        is_valid=user.validate_record(requestbody['username'],requestbody['email'],requestbody['password'],requestbody['fname'],requestbody['lname'])
        if(is_valid == True):
            new_user=User(password=requestbody['password'],user_name=requestbody['username'],email=requestbody['email'],first_name=requestbody['fname'],last_name=requestbody['lname'])
            new_user.save()
            profile =  Profile(user= new_user)
            profile.save()
            access_token = create_access_token(identity = new_user.email)
            refresh_token = create_refresh_token(identity = new_user.email)
            return jsonify({'code': 200,'status': 'Success','access-token':access_token,'refresh-token':refresh_token})
        else:
            error = is_valid
            return jsonify({'code': 400,'status': error})
            disconnect(alias='around')
    except Exception as e:
        return jsonify({'code': 500,'status': 'Internal Server Error'})
        disconnect(alias='around')

          
@app.route('/validateusername',methods = ['POST'])
@cross_origin()
def validate_username():
    requestbody =json.loads(request.data)
    try:
        connect(alias='around')
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
        connect(alias='around')
        user=User()
        is_valid = user.validate_email(requestbody['email'])
        if(is_valid == True):
            return jsonify({'code': 200,'status': 'Success'})
        return jsonify({'code': 400,'status': is_valid})
    except Exception as e:
        print(e)
        return jsonify({'code': 500,'status': 'Internal Server Error'})
@app.route('/validateemailforgotpassword',methods = ['POST'])
@cross_origin()
def validate_forgot_password_email():
    requestbody =json.loads(request.data)
    try:
        connect(alias='around')
        user=User()
        is_valid = user.validate_forgot_password_email(requestbody['email'])
        if(is_valid == True):
            return jsonify({'code': 200,'status': 'Success'})
        return jsonify({'code': 400,'status': is_valid})
    except Exception as e:
        print(e)
        return jsonify({'code': 500,'status': 'Internal Server Error'})

@app.route('/validateotpupdatenewpassword',methods = ['POST'])
@cross_origin()
def validate_otp_update_forgot_password():
    requestbody =json.loads(request.data)
    try:
        connect(alias='around')
        user=User()
        is_valid = user.validate_and_update_otp_new_password(requestbody)
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
            connect(alias='around')
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
        connect(alias='around')
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
    connect(alias='around')
    jti = get_raw_jwt()['jti']
    blacklist =TokenBlacklist()
    blacklist.add_to_blacklist(jti)
    return jsonify({'code': 200,'status': 'Successfully logged out'})

@app.route('/auth/forgot',methods = ['POST'])
@cross_origin()
def forgot_password():
    requestbody =json.loads(request.data)
    if requestbody:
        connect(alias='around')
        user= User()
        if(user.forgot_password_otp(requestbody)):
            return jsonify({'code': 200,'status': 'Success'})
        return jsonify({'code': 400,'status': 'Something went wrong.'})
    return jsonify({'code': 400,'status': 'Something went wrong.'})
    
@app.route('/auth/guard/',methods = ['POST'])
@cross_origin()
def auth_guard():
    requestbody =json.loads(request.data)
    if requestbody:
        connect(alias='around')
        if(1==1):
            return jsonify({'code': 200,'status': 'Success'})
        return jsonify({'code': 400,'status': 'Something went wrong.'})
    return jsonify({'code': 400,'status': 'Something went wrong.'})
@app.route('/auth/reset',methods = ['POST'])
@cross_origin()
def reset_password():
    requestbody =json.loads(request.data)
    if requestbody:
        connect(alias='around')
        user= User()
        if(user.reset_password(requestbody)):
            return jsonify({'code': 200,'status': 'Success'})
        return jsonify({'code': 400,'status': 'Incorrect OTP.'})
    return jsonify({'code': 400,'status': 'Something went wrong.'})

'''Post services'''
@app.route('/post/',methods = ['POST'])
@jwt_required
@cross_origin()
def save_post():
    requestbody =json.loads(request.data)
    try:
        claims = get_jwt_claims()
        connect(alias='around')
        post=Post()
        is_valid = post.validate_post(requestbody,claims)
        if is_valid:
            return jsonify({'code': 200,'status': 'Saved successfully','data' :is_valid})
        return jsonify({'code': 400,'status': 'Something went wrong.'})
    except Exception as e:
        return jsonify({'code': 500,'status': 'Internal Server Error'})
    
@app.route('/post/all/',methods = ['GET'])
@jwt_required
@cross_origin()
def view_all_post():
    try:
        claims = get_jwt_claims()
        connect(alias='around')
        post=Post()
        is_valid = post.view_all_post(claims)
        if is_valid:
            return jsonify({'code': 200,'status': 'Success','posts' :is_valid})
        return jsonify({'code': 400,'status': 'No Posts','posts':[]})
    except Exception as e:
        print(e,"error:")
        return jsonify({'code': 500,'status': 'Internal Server Error'})
    
@app.route('/post/<post_id>',methods = ['GET'])
@jwt_optional
@cross_origin()
def view_post(post_id):
    try:
        claims = get_jwt_claims()
        connect(alias='around')
        post=Post()
        is_valid = post.view_post(post_id,claims)
        if is_valid:
            return jsonify({'code': 200,'status': 'Success','data' :is_valid})
        return jsonify({'code': 400,'status': 'Something went wrong.'})
    except Exception as e:
        print(e,"except")
        return jsonify({'code': 500,'status': 'Internal Server Error'})
    
    
@app.route('/post/delete',methods = ['POST'])
@jwt_required
@cross_origin()
def delete_post():
    try:
        post_id = json.loads(request.data).get('post',False)
        if post_id:
            claims = get_jwt_claims()
            connect(alias='around')
            post=Post()
            is_valid = post.delete_post(post_id,claims)
            if is_valid:
                return jsonify({'code': 200,'status': 'Success'})
            return jsonify({'code': 400,'status': 'Post already deleted'})
        return jsonify({'code': 400,'status': 'Something went wrong.'})
    except Exception as e:
        print(e)
        return jsonify({'code': 500,'status': 'Internal Server Error'})
    
'''like object services
    req {'post' :post_id}
'''
@app.route('/post/like',methods = ['POST'])
@jwt_required
@cross_origin()
def like_post():
    requestbody =json.loads(request.data)
    try:
        claims = get_jwt_claims()
        connect(alias='around')
        post=Post()
        res = post.like_post(requestbody,claims)
        if res:
            return jsonify({'code': 200,'status': 'Success'})
        return jsonify({'code': 400,'status': 'Something went wrong.'})
    except Exception as e:
        print(e)
        return jsonify({'code': 500,'status': 'Internal Server Error'})
    
@app.route('/post/dislike',methods = ['POST'])
@jwt_required
@cross_origin()
def dislike_post():
    requestbody =json.loads(request.data)
    try:
        claims = get_jwt_claims()
        connect(alias='around')
        post=Post()
        res = post.dislike_post(requestbody,claims)
        if res:
            return jsonify({'code': 200,'status': 'Success'})
        return jsonify({'code': 400,'status': 'Something went wrong.'})
    except Exception as e:
        print(e)
        return jsonify({'code': 500,'status': 'Internal Server Error'})
        
    
'''search services'''
@app.route('/search',methods = ['POST'])
@jwt_required
@cross_origin()
def search():
    try:
        requestbody =json.loads(request.data)
        claims = get_jwt_claims()
        connect(alias='around')
        user=User()
        is_valid = user.search(requestbody,claims)
        return jsonify({'code': 200,'status': 'Success','data':is_valid})
    except Exception as e:
        print(e)
        return jsonify({'code': 500,'status': 'Something went wrong'})

'''Profile services'''
@app.route('/profile/upload',methods = ['POST'])
@jwt_required
@cross_origin()
def profile_upload():
    try:
        requestbody =json.loads(request.data)
        claims = get_jwt_claims()
        connect(alias='around')
        profile=Profile()
        is_valid = profile.upload_image(requestbody,claims)
        if is_valid:
            return jsonify(is_valid)
        return jsonify({'code': 500,'status': 'Something went wrong'})
    except Exception as e:
        print(e)
        return jsonify({'code': 500,'status': 'Something went wrong'})

'''Comment Service'''
@app.route('/comment/create',methods = ['POST'])
@jwt_required
@cross_origin()
def add_comment():
    try:
        requestbody =json.loads(request.data)
        claims = get_jwt_claims()
        connect(alias='around')
        comment=Comment()
        is_valid = comment.add_comment(requestbody,claims)
        if is_valid:
            return jsonify(is_valid)
        return jsonify({'code': 500,'status': 'Something went wrong'})
    except Exception as e:
        print(e)
        return jsonify({'code': 500,'status': 'Something went wrong'})

@app.route('/comment/like',methods = ['POST'])
@jwt_required
@cross_origin()
def like_comment():
    requestbody =json.loads(request.data)
    try:
        claims = get_jwt_claims()
        connect(alias='around')
        comment=Comment()
        res = comment.like_comment(requestbody,claims)
        if res:
            return jsonify({'code': 200,'status': 'Success'})
        return jsonify({'code': 400,'status': 'Something went wrong.'})
    except Exception as e:
        print(e)
        return jsonify({'code': 500,'status': 'Internal Server Error'})
    
@app.route('/comment/dislike',methods = ['POST'])
@jwt_required
@cross_origin()
def dislike_comment():
    requestbody =json.loads(request.data)
    try:
        claims = get_jwt_claims()
        connect(alias='around')
        comment=Comment()
        res = comment.dislike_comment(requestbody,claims)
        if res:
            return jsonify({'code': 200,'status': 'Success'})
        return jsonify({'code': 400,'status': 'Something went wrong.'})
    except Exception as e:
        print(e)
        return jsonify({'code': 500,'status': 'Internal Server Error'})
    
if __name__ == '__main__':
    db = MongoEngine(app)
    serve(app,host='127.0.0.1', port=5000)
    
    
    