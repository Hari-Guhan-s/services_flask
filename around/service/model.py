from mongoengine import *
import re
import datetime
from passlib.hash import pbkdf2_sha256 as sha256
import json
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
    profile_image = ImageField()
    joined_on = DateTimeField(default=datetime.datetime.now())
    last_sign_in = DateTimeField()
    language=StringField(default='en/US',required=True)
    blocklist =ListField(ReferenceField('self'))
    active = BooleanField(default=True)
    
class TokenBlacklist(Document):
    
    token = StringField(required=True,primary_key=True)
    
    def validate_token(self,token):
        if TokenBlacklist.objects(token=token):
            return True
        else:
            return False
        
    def add_to_blacklist(self,token):
        add_token = TokenBlacklist(token=token)
        add_token.save()
    
class Post(Document):
    CHOICES=('Public','Private','Me')
    author = ReferenceField(User,required=True)
    mentions =ListField(ReferenceField(User))
    created_time= DateTimeField(default=datetime.datetime.now(),required=True)
    updated_time= DateTimeField()
    post=StringField()
    privacy= StringField(choices=CHOICES,default='Public')
    likes = LongField(default= 0)
    liked_by = ListField(ReferenceField(User))
    dislikes = LongField(default= 0)
    disliked_by = ListField(ReferenceField(User))
    shares = LongField(default= 0)
    attachments = ListField(ReferenceField(Document))
    hashtags = ListField()
    active = BooleanField(default=True)
    
    def validate_post(self,post,claims):
        if post and claims:
            attachment =[]
            mention=[]
            for media in post.get('mention',[]):
                m = MediaAttachment.objects(id=media)
                attachment.append(m)
            for user in post.get('media',[]):
                u = User.objects(id=user)
                mention.append(u)
            author = User.objects(id=claims['user_id']).first()
            new_post =Post(author=author,post=post['post'],privacy=post.get('privacy'),hashtags=post.get('hashtags',[]),attachments=attachment,mentions=mention)
            new_post.save()
            return str(new_post.id)
        return False
    
    def view_post(self,post_id,claims):
        if post_id:
            post =Post.objects(id=post_id,active=True).exclude('active')
            if post:
                return  json.loads(post.to_json())
            return False
        return False
            
    
class MediaAttachment(Document):
    filename = StringField(required=True)
    type = StringField(required= True)
    content = FileField(required=True)
    uploaded_on = DateTimeField(required=True,default=datetime.datetime.now())
    uploaded_by = ReferenceField(User,dbref=True,required=True)
    active = BooleanField(default=True)
    
    def upload_media_attachment(self,data):
        pass