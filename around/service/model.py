from mongoengine import *
from mongoengine.queryset.visitor import Q
import re
import datetime
from passlib.hash import pbkdf2_sha256 as sha256
from random import randint
from io import BytesIO
import base64
import traceback
from PIL import Image
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
    
    def check_user_session(self,claims):
        if claims:
            user = User.objects(id = claims.get('user_id'),active=True).first()
            if user:
                return True
            return False
        return False
            
    
    def to_json(self,claims=None):
        profile = Profile.objects(user= self).first()
        if self.active:
            return{'user_name':self.user_name,'name':str(self.first_name)+' '+str(self.last_name),'language':self.language,'profile_image':base64.b64encode(profile.profile_image_orginal.read()) if profile.profile_image_orginal else ''}
        return {'user_name':'in_active_user','name':'Inactive User','language':'en/US','profile_image':''}
    
    def search(self,search,claims):
        if search.get('search') and claims:
            value = search.get('search')
            user =  claims.get('user_id')
            results = User.objects[:5].filter((Q(email =value) | Q(phone = value) | Q(user_name__istartswith = value) | Q(first_name__istartswith = value)) & Q(active = True))
            return [res.to_json(claims) for res in results  ]
        return False
    
    def get_user(self,claims):
        if claims:
            return User.objects(id = claims.get('user_id'),active=True).first()
        return False
    
    first_name = StringField(max_length=200, required=True)
    last_name = StringField(max_length=200, required=True)
    user_name =StringField()
    email = EmailField(required=True,unique= True)
    phone = StringField(unique=True,sparse=True)
    password = StringField(required=True)
    joined_on = DateTimeField(default=datetime.datetime.now())
    last_sign_in = DateTimeField()
    language=StringField(default='en/US',required=True)
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
    profile_image_orginal = FileField()
    profile_image_small = FileField()
    
    def follow_request(self,req,claims):
        pass

    def upload_image(self,req,claims):
        if req and claims and req.get('data'):
            author = User.objects(id=claims.get('user_id')).first()
            profile = Profile.objects(user= author).first()
            if not profile:
                profile = Profile(user=author).save()
            #im = Image.open(BytesIO(base64.b64decode(req.get('data'))))
            #imgByteArrThumbnail = BytesIO()
            #im.resize((int(im.size[0]/.2),int(im.size[1]/.2)),3).save(imgByteArrThumbnail,'PNG')
            #print(base64.b64encode(imgByteArrThumbnail.getvalue()))
            profile.profile_image_orginal=base64.b64decode(req.get('data'))
            #profile.profile_image_small=imgByteArrThumbnail.getvalue()
            profile.save()
            return {'code':200,'status':'Profile image uploaded successfully.'}
        return False
    
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
    file_extension = StringField(required=True)
    content = FileField(required=True)
    uploaded_on = DateTimeField(required=True,default=datetime.datetime.now())
    uploaded_by = ReferenceField(User,required=True)
    active = BooleanField(default=True)
    
    def to_json(self):
        return {'id':str(self.id),'file_name':self.filename,'type':self.type,'data':base64.b64encode(self.content.read()),'file_extension':self.file_extension}

class Comment(Document):
    user = ReferenceField(User,required=True)
    mentions =ListField(ReferenceField(User))
    created_time= DateTimeField(default=datetime.datetime.now(),required=True)
    updated_time= DateTimeField(default=datetime.datetime.now())
    comment=StringField(required=True,default='')
    liked_by = ListField(ReferenceField(User))
    disliked_by = ListField(ReferenceField(User))
    attachments = ListField(ReferenceField(MediaAttachment))
    hashtags = ListField()
    active = BooleanField(default=True)

    def delete_comment(self,comment_id,claims):
        if comment_id:
            user = User.get_user(self,claims=claims)
            comment=Comment.objects(id=comment_id,active=True,user = user).first()
            if comment:
                    comment.active=False
                    comment.save()
                    return True
            return False
        return False
    
    def like_comment(self,req,claims):
        if req.get('comment') and claims:
            commment_id =req.get('comment')
            comment =Comment.objects(id=commment_id,active=True).first()
            user = User.get_user(self,claims=claims)
            if comment and user:
                if user not in comment.liked_by:
                    comment.disliked_by.remove(user) if user in comment.disliked_by else False
                    comment.liked_by.append(user.id)
                    comment.save()
                    return True
                else:
                    comment.disliked_by.remove(user) if user in comment.disliked_by else False
                    comment.liked_by.remove(user)
                    comment.save()
                    return True
            return False
        return False
    
    def dislike_comment(self,req,claims):
        if req.get('comment') and claims:
            comment =Comment.objects(active=True,id=req.get('comment')).first()
            user = User.get_user(self,claims=claims)
            if comment and user:
                if user not in comment.disliked_by:
                    comment.liked_by.remove(user) if user in comment.liked_by else False
                    comment.disliked_by.append(user.id)
                    comment.save()
                    return True
                else:
                    comment.liked_by.remove(user) if user in comment.liked_by else False
                    comment.disliked_by.remove(user)
                    comment.save()
                    return True
                return False
            return False
        return False

    def add_comment(self,req,claims):
        if req.get('comment') and req.get('post_id') and claims:
            attachment =[]
            mention=[]
            user = User.get_user(self,claims=claims)
            post = Post.objects(active=True,id=req.get('post_id')).first()
            if user and post:
                for media in req.get('attachments',[]):
                    m = MediaAttachment(filename=media.get('file_name'),file_extension=media.get('file_ext'),type=media.get('file_type'),content=base64.b64decode(media.get('data')),uploaded_by=author).save()
                    attachment.append(m)
                for user in req.get('mention',[]):
                    u = User.objects(id=user)
                    mention.append(u)
                comment = Comment(comment=req.get('comment'),user= user,attachments=attachment,mentions=mention)
                comment.save()
                post.comments.append(comment)
                post.save()
                return {"code":200,"status":"Success","comment_id":str(comment.id)}
            return False
        return False

    def to_json(self,claims):
        user= User.get_user(self,claims=claims)
        likes_by=[user.to_json() for user in self.liked_by[:limit]]
        dislikes_by=[user.to_json() for user in self.disliked_by[:limit]]
        attachments=[attachment.to_json() for attachment in self.attachments[:limit]]
        liked = True if claims and user in self.liked_by else False
        disliked = True if claims and user in self.disliked_by  else False
        data={'id':str(self.id),'author':self.user.to_json(claims),'created_on':self.created_time,'updated_on':self.updated_time,'comment':self.comment,'likes':len(self.liked_by),'liked_by':likes_by,'dislikes':len(self.disliked_by),'disliked_by':dislikes_by,'hashtags':self.hashtags,'attachments':attachments,'liked':liked,'dislike':disliked }
        return data


class Post(Document):
    
    
    CHOICES=('Public','Private','Me')
    author = ReferenceField(User,required=True)
    mentions =ListField(ReferenceField(User))
    created_time= DateTimeField(default=datetime.datetime.now(),required=True)
    updated_time= DateTimeField(default=datetime.datetime.now())
    topic=StringField(required=True,default='')
    post=StringField()
    privacy= StringField(choices=CHOICES,default='Public')
    liked_by = ListField(ReferenceField(User))
    disliked_by = ListField(ReferenceField(User))
    shares = LongField(default= 0)
    attachments = ListField(ReferenceField(MediaAttachment))
    hashtags = ListField()
    active = BooleanField(default=True)
    comments = ListField(ReferenceField(Comment))
    
    def to_json(self,claims=None):
        user= User.objects(active=True,id=claims.get('user_id')).first()
        likes_by=[user.to_json() for user in self.liked_by[:limit]]
        dislikes_by=[user.to_json() for user in self.disliked_by[:limit]]
        attachments=[attachment.to_json() for attachment in self.attachments[:limit]]
        comments=[comment.to_json(claims)for comment in self.comments[:limit]]
        liked = True if claims and user in self.liked_by else False
        disliked = True if claims and user in self.disliked_by  else False
        data={'id':str(self.id),'author':self.author.to_json(claims),'created_on':self.created_time,'updated_on':self.updated_time,'post':self.post,'topic':self.topic,'likes':len(self.liked_by),'liked_by':likes_by,'dislikes':len(self.disliked_by),'disliked_by':dislikes_by,'shares':self.shares,'privacy':self.privacy,'hashtags':self.hashtags,'attachments':attachments,'liked':liked,'dislike':disliked,'comments':comments}
        return data
    
    def validate_post(self,post,claims):
        if post and claims:
            attachment =[]
            mention=[]
            author = User.objects(id=claims['user_id']).first()
            for media in post.get('attachments',[]):
                m = MediaAttachment(filename=media.get('file_name'),file_extension=media.get('file_ext'),type=media.get('file_type'),content=base64.b64decode(media.get('data')),uploaded_by=author).save()
                attachment.append(m)
            for user in post.get('mention',[]):
                u = User.objects(id=user)
                mention.append(u)
            new_post =Post(author=author,post=post['post'],topic=post.get('topic'),privacy=post.get('privacy'),hashtags=post.get('hashtags',[]),attachments=attachment,mentions=mention)
            return new_post.save().to_json(claims)
        return False
    
    def view_post(self,post_id,claims):
        if post_id:
            post =Post.objects(id=post_id,active=True).exclude('active').first()
            if post:
                return post.to_json(claims)
            return False
        return False
    
    def view_all_post(self,claims):
        if claims:
            posts =Post.objects(active=True,privacy='Public').order_by('-created_time')
            if posts:
                return [post.to_json(claims) for post in posts ]
            return False
        return False
    
    def delete_post(self,post_id,claims):
        if post_id:
            post=Post.objects(id=post_id,active=True).first()
            if post:
                if post.author == User.get_user(self,claims=claims):
                    post.active=False
                    post.save()
                    return True
                return False
            return False
        return False
    
    def like_post(self,req,claims):
        if req.get('post') and claims:
            post_id =req.get('post')
            posts =Post.objects(id=post_id,active=True).first()
            user = User.get_user(self,claims=claims)
            if posts and user:
                if user not in posts.liked_by:
                    posts.disliked_by.remove(user) if user in posts.disliked_by else False
                    posts.liked_by.append(user.id)
                    posts.save()
                    return True
                else:
                    posts.disliked_by.remove(user) if user in posts.disliked_by else False
                    posts.liked_by.remove(user)
                    posts.save()
                    return True
            return False
        return False
    
    def dislike_post(self,req,claims):
        if req.get('post') and claims:
            posts =Post.objects(active=True,id=req.get('post')).first()
            user = User.objects(active=True,id=claims.get('user_id')).first()
            if posts and user:
                if user not in posts.disliked_by:
                    posts.liked_by.remove(user) if user in posts.liked_by else False
                    posts.disliked_by.append(user.id)
                    posts.save()
                    return True
                else:
                    posts.liked_by.remove(user) if user in posts.liked_by else False
                    posts.disliked_by.remove(user)
                    posts.save()
                    return True
                return False
            return False
        return False
