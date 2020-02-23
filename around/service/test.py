from api import app
from flask import json
from flask_mongoengine import MongoEngine
from io import BytesIO
from base64 import b64encode
from os import getcwd
import traceback

auth_token =''
post_id =''
img_file =''
test_email =''
test_password =''
test_user_name =''
comment_id=''

def test_auth_services():
    print('=== Testing Auth Services ====')
    'Validate username'
    response = app.test_client().post(
        '/validateusername',
        data=json.dumps({
    "username": "joyalbaby2011",
    }),
        content_type='application/json',
    )
    data = json.loads(response.get_data(as_text=True))
    try:
        assert data['code'] == 400
        print('Validate Username : OK' )
    except AssertionError:
        print('Validate Username : FAIL')

    'Validate email'
    response = app.test_client().post(
        '/validateemail',
        data=json.dumps({
    "email": "joyalbaby@outlook.com",
    }),
        content_type='application/json',
    )
    data = json.loads(response.get_data(as_text=True))
    try:
        assert data['code'] == 400
        print('Validate Email : OK' )
    except AssertionError:
        print('Validate Email : FAIL')

    'Validate Forgot Password'
    response = app.test_client().post(
        '/auth/forgot',
        data=json.dumps({
    "email": "joyalbaby@outlook.com",
    }),
        content_type='application/json',
    )
    data = json.loads(response.get_data(as_text=True))
    try:
        assert data['code'] == 200
        print('Validate Forgot Password : OK' )
    except AssertionError:
        print('Validate Forgot Password : FAIL')
    
    'Validate Reset Password'
    response = app.test_client().post(
        '/auth/reset',
        data=json.dumps({
    "email":"joyalbaby@outlook.com",
    "otp":"845652",
    "password":"joyalbaby1234"
    }),
        content_type='application/json',
    )
    data = json.loads(response.get_data(as_text=True))
    try:
        assert data['status'] == "Incorrect OTP."
        print('Validate Reset Password : OK' )
    except AssertionError:
        print('Validate Reset Password : FAIL')

    test_sign_in('joyalbaby@outlook.com','joyalbaby0675')

    'Validate Session'
    response = app.test_client().get(
        '/auth/validate/',
        headers={"content_type":"application/json","Authorization":"Bearer "+str(auth_token)},
    )
    data = json.loads(response.get_data(as_text=True))
    try:
        assert data['code'] == 200
        print('Session Validation : OK' )
    except AssertionError:
        print('Session Validation : FAIL')
    test_sign_out()
    'In Valid Session'
    response = app.test_client().get(
        '/auth/validate/',
        headers={"content_type":"application/json","Authorization":"Bearer "+str(auth_token)},
    )
    data = json.loads(response.get_data(as_text=True))
    try:
        assert data.get('status') == "Token has been revoked"
        print('Session Out : OK' )
    except AssertionError:
        print('Session Out : FAIL')

def test_sign_in(email,password):
    'Validate Sign In'
    response = app.test_client().post(
        '/auth/signin/',
        data=json.dumps({
    "email": email,
    "password": password
    }),
        content_type='application/json',
    )
    global test_email 
    test_email=email
    global test_password 
    test_password=password
    data = json.loads(response.get_data(as_text=True))
    try:
        assert data.get('code') == 200
        assert data.get('access-token')
        global auth_token 
        auth_token = data.get('access-token')
        print('Sign in : OK' )
    except AssertionError:
        print('Sign in : FAIL')

def test_sign_out():
    'Validate Sign Out'
    response = app.test_client().get(
        '/auth/signout',
        headers={"content_type":"application/json","Authorization":"Bearer "+str(auth_token)},
    )
    data = json.loads(response.get_data(as_text=True))
    try:
        assert data.get('code') == 200
        print('Sign Out : OK' )
    except AssertionError:
        print('Sign Out : FAIL')

def test_post_services():
    print('=== Testing Post Services ====')
    get_base64_image_file('image.png')

    'Validate Create Post'
    response = app.test_client().post(
        '/post/',
        data=json.dumps({
            "post": "This is the post content 2",
            "topic": "this is the title 2",
            "privacy": "Public",
            "attachments": [
                
            ]
        }),
        headers={"content_type":"application/json","Authorization":"Bearer "+str(auth_token)},
    )
    data = json.loads(response.get_data(as_text=True))    
    try:
        assert data.get('code') == 200
        global post_id
        post_id = data.get('data').get('id')
        print('Validate Create Post : OK' )
    except AssertionError:
        print('Validate Create Post : FAIL')
    except Exception:
        print(traceback.print_exc())

    'Validate View All Post'
    response = app.test_client().get(
        '/post/all/',
        headers={"content_type":"application/json","Authorization":"Bearer "+str(auth_token)},
    )
    data = json.loads(response.get_data(as_text=True))    
    try:
        assert data.get('code') == 200
        print('Validate View All Post : OK' )
    except AssertionError:
        print('Validate View All Post : FAIL')

    'Validate View Post'
    response = app.test_client().get(
        '/post/'+post_id,
        headers={"content_type":"application/json","Authorization":"Bearer "+str(auth_token)},
    )
    data = json.loads(response.get_data(as_text=True))    
    try:
        assert data.get('code') == 200
        print('Validate View Post : OK' )
    except AssertionError:
        print('Validate View Post : FAIL')

    'Validate Like Post'
    response = app.test_client().post(
        '/post/like',
        data = json.dumps({
            "post":post_id
        }),
        headers={"content_type":"application/json","Authorization":"Bearer "+str(auth_token)},
    )
    data = json.loads(response.get_data(as_text=True))    
    try:
        assert data.get('code') == 200
        print('Validate Like Post : OK' )
    except AssertionError:
        print('Validate Like Post : FAIL')

    'Validate Dislike Post'
    response = app.test_client().post(
        '/post/dislike',
        data = json.dumps({
            "post":post_id
        }),
        headers={"content_type":"application/json","Authorization":"Bearer "+str(auth_token)},
    )
    data = json.loads(response.get_data(as_text=True))    
    try:
        assert data.get('code') == 200
        print('Validate Dislike Post : OK' )
    except AssertionError:
        print('Validate Dislike Post : FAIL')

def test_misc_services():
    'Validate Search'
    response = app.test_client().post(
        '/search',
        data = json.dumps({"search":"joyalbaby"}),
        headers={"content_type":"application/json","Authorization":"Bearer "+str(auth_token)},
    )

    data = json.loads(response.get_data(as_text=True))
    try:
        assert data.get('code') == 200
        print('Validate Search : OK' )
    except AssertionError:
        print('Validate Search : FAIL')    

def test_sign_up_services(username,email):
    print('=== Sign Up Services ===' )
    'Validate Sign Up'
    response = app.test_client().post(
        'auth/signup/',
        data = json.dumps({"fname":"joyal",
        "lname":"baby",
        "password":"1234Welcome",
        "username":username,
        "email":email
        }),
        headers={"content_type":"application/json"},
    )

    data = json.loads(response.get_data(as_text=True))
    try:
        print(data)
        assert data.get('code') == 200
        global test_email 
        test_email = email
        global test_password 
        test_password ='1234Welcome'
        print('Validate Sign Up : OK' )
    except AssertionError:
        print('Validate Sign Up : FAIL')    

def test_comment_services():
    'Validate Create Comment'
    response = app.test_client().post(
        '/comment/create',
        data = json.dumps({
            "post_id":post_id,
            "comment":"This is a test comment"
        }),
        headers={"content_type":"application/json","Authorization":"Bearer "+str(auth_token)},
    )
    data = json.loads(response.get_data(as_text=True))    
    try:
        assert data.get('code') == 200
        global comment_id
        comment_id =data.get('comment_id')
        print('Validate Create Comment : OK' )
    except AssertionError:
        print('Validate Create Comment : FAIL')

    'Validate Like Comment'
    response = app.test_client().post(
        '/comment/like',
        data = json.dumps({
            "comment":comment_id
        }),
        headers={"content_type":"application/json","Authorization":"Bearer "+str(auth_token)},
    )
    data = json.loads(response.get_data(as_text=True))    
    try:
        assert data.get('code') == 200
        print('Validate Like Comment : OK' )
    except AssertionError:
        print('Validate Like Comment : FAIL')

    'Validate Dislike Comment'
    response = app.test_client().post(
        '/comment/dislike',
        data = json.dumps({
            "comment":comment_id
        }),
        headers={"content_type":"application/json","Authorization":"Bearer "+str(auth_token)},
    )
    data = json.loads(response.get_data(as_text=True))    
    try:
        assert data.get('code') == 200
        print('Validate Dislike Comment : OK' )
    except AssertionError:
        print('Validate Dislike Comment : FAIL')

    


def test_remove_post():
    'Validate Delete Post'
    response = app.test_client().post(
        '/post/delete',
        data = json.dumps({
            "post":post_id
        }),
        headers={"content_type":"application/json","Authorization":"Bearer "+str(auth_token)},
    )
    data = json.loads(response.get_data(as_text=True))    
    try:
        assert data.get('code') == 200
        print('Validate Delete Post : OK' )
    except AssertionError:
        print('Validate Delete Post : FAIL')    

def get_base64_image_file(file_name):
    path='/home/joyalbaby/git commit/services_flask/around/service/'
    with open(path+file_name, "rb") as file:
        global img_file
        my_string = b64encode(file.read())
        img_file = my_string.decode('utf-8')

if __name__ == '__main__':
    db = MongoEngine(app)
    test_auth_services()
    test_sign_in('joyalbaby@outlook.com','joyalbaby0675')
    test_post_services()
    test_comment_services()
    test_misc_services()
    test_remove_post()
    test_sign_out()
    print('========= Testing Invalid Session ==========')
    test_post_services()
    test_comment_services()
    test_misc_services()
    test_remove_post()
    test_sign_out()
    test_sign_up_services('joyalbaby2011','joyalbaby@outlook.com')
    test_sign_in(test_email,test_password)
    print('======== Testing new user Session =========')
    test_post_services()
    test_comment_services()
    test_misc_services()
    #test_remove_post()
    test_sign_out()
    print('=== Test Completed ===')
    