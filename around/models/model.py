from mongoengine import *
import re
import datetime
from passlib.hash import pbkdf2_sha256 as sha256

class User(Document):
    
    def validate_record(self,username,email,password,first_name,last_name):
        if not first_name:
            return "Please enter the first name"
        if not last_name:
            return "Please enter the last name"  
        if User.objects(user_name=username):
            return "Sorry, The username already exists"
        if not email:
            return "Please enter the email"
        elif not re.match("[^@]+@[^@]+\.[^@]+", email):
                return "Sorry, This looks like an invalid email address"
        if User.objects(email=email):
            return "Sorry, The email already registered"         
        return True
    
    def validate_username(self,username):
        if username:
            if User.objects(user_name=username):
                return "Sorry, The username already exists"
            return True
        return False
    
    def validate_email(self,email):
        if email:
            if not re.match("[^@]+@[^@]+\.[^@]+", email):
                return "Sorry, This looks like an invalid email address"
            if User.objects(email=email):
                return "Sorry, This email is already registered"
            return True
        return False
    
    def validate_sign_in(self,email,password):
        if email and password:
            print('password')
            print(password)
            user = User.objects(email=email).first()
            if user and sha256.verify(password, user.password):
                return user.email
        return False
    
    first_name = StringField(max_length=200, required=True)
    last_name = StringField(max_length=200, required=True)
    user_name =StringField()
    email = EmailField(required=True,unique= True)
    password = StringField(required=True)
    location  = PointField()
    last_sign_in = DateTimeField(default=datetime.datetime.now())
    
    