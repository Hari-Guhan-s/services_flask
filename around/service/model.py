from mongoengine import *
from mongoengine.queryset.visitor import Q
import re
import datetime
from passlib.hash import pbkdf2_sha256 as sha256
from random import randint
limit = 5
offset = 0

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
            user = User.objects(email=email).first()
            if user and sha256.verify(password, user.password):
                return user.email
        return False
    
    def forgot_password_otp(self,req):
        if req:
            data = req.get('phone',False) or req.get('email',False)
            user =User.objects(Q(email =data ) | Q(phone= data)).first()
            if user and data:
                otp = randint(100000, 999999)
                print('otp===')
                print(otp)
                user.otp = sha256.hash(str(otp))
                user.save()
                return True
            return False
        return False
    
    def reset_password(self,req):
        if req:
            otp = req.get('otp',False)
            data = req.get('phone',False) or req.get('email',False)
            password = req.get('password',False)
            user =User.objects(Q(email =data ) | Q(phone= data)).first()
            if user and user.otp and sha256.verify(str(otp), user.otp):
                user.password = sha256.hash(password)
                user.otp=''
                user.save()
                return True
            return False
        return False
            
    
    def to_json(self):
        if self.active:
            return{'user_name':self.user_name,'name':str(self.first_name)+' '+str(self.last_name),'language':self.language}
        return {'user_name':'in_active_user','name':'Inactive User','language':'en/US'}
    
    first_name = StringField(max_length=200, required=True)
    last_name = StringField(max_length=200, required=True)
    user_name =StringField()
    email = EmailField(required=True,unique= True)
    phone = StringField(unique=True,sparse=True)
    password = StringField(required=True)
    joined_on = DateTimeField(default=datetime.datetime.now())
    last_sign_in = DateTimeField()
    language=StringField(default='en/US',required=True)
    #profile_id = ReferenceField(Profile)
    otp = StringField() 
    active = BooleanField(default=True)

class Profile(Document):
    user = ReferenceField(User)
    followers = ListField(ReferenceField(User))
    follow_request = ListField(ReferenceField(User))
    follow_request_given =ListField(ReferenceField(User))
    following = ListField(ReferenceField(User))
    blocklist =ListField(ReferenceField(User))
    blocked_by =ListField(ReferenceField(User))
    location  = PointField()
    profile_image = ImageField()
    
    def follow_request(self,req,claims):
        pass

    
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
        
class MediaAttachment(Document):
    filename = StringField(required=True)
    type = StringField(required= True)
    content = FileField(required=True)
    uploaded_on = DateTimeField(required=True,default=datetime.datetime.now())
    uploaded_by = ReferenceField(User,required=True)
    active = BooleanField(default=True)
    
    def to_json(self):
        return {'id':str(self.id),'file_name':self.filename,'type':self.type,'content':self.content,'size':len(self.content)}
    
    def upload_media_attachment(self,data):
        pass
    
class Post(Document):
    
    
    CHOICES=('Public','Private','Me')
    author = ReferenceField(User,required=True)
    mentions =ListField(ReferenceField(User))
    created_time= DateTimeField(default=datetime.datetime.now(),required=True)
    updated_time= DateTimeField(default=datetime.datetime.now())
    post=StringField()
    privacy= StringField(choices=CHOICES,default='Public')
    liked_by = ListField(ReferenceField(User))
    disliked_by = ListField(ReferenceField(User))
    shares = LongField(default= 0)
    attachments = ListField(ReferenceField(MediaAttachment))
    hashtags = ListField()
    active = BooleanField(default=True)
    
    def to_json(self):
        likes_by=[user.to_json() for user in self.liked_by[:limit]]
        dislikes_by=[user.to_json() for user in self.disliked_by[:limit]]
        attachments=[attachment.to_json() for attachment in self.attachments[:limit]]
        data={'id':str(self.id),'author':self.author.to_json(),'created_on':self.created_time,'updated_on':self.updated_time,'post':self.post,'likes':len(self.liked_by),'liked_by':likes_by,'dislikes':len(self.disliked_by),'disliked_by':dislikes_by,'shares':self.shares,'privacy':self.privacy,'hashtags':self.hashtags,'attachments':attachments}
        return data
    
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
            post =Post.objects(id=post_id,active=True).exclude('active').first()
            if post:
                return  post.to_json()
            return False
        return False
    
    def delete_post(self,post_id,claims):
        if post_id:
            post=Post.objects(id=post_id).first()
            if post:
                if post.author == claims.get('user_id',False):
                    post.active=False
                    post.save()
                    return True
                return False
            return False
        return False
    
    #===========================================================================
    # def search_around(self,search,claims):
    #     if search.get('search') and search.get('value'):
    #         if search.get('search') == 'tags':    
    #             post = 
    #===========================================================================
    
    
