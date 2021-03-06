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
import re
from flask import current_app
from flask_mail import Message
import configparser
import os
import logging
import pathlib


#configuration reader
config_param = configparser.ConfigParser()
dir_name=pathlib.Path(__file__).absolute().parent.parent
dir_name=dir_name.joinpath('config')
dir_name=dir_name.joinpath('app.cfg')
config_param.read(dir_name)


limit = config_param['General'].getint('limit')
offset = config_param['General'].getint('offset')
resend_password_time_limit= config_param['General'].getint('resend_password_time_limit')
posts_view_threshold = config_param['General'].getint('posts_view_threshold')
activity_threshold = config_param['General'].getint('activity_threshold')

config={}
config['URL'] =config_param['General'].get('URL').strip()

class User(Document):
    
    def validate_record(self,username,email,password,first_name,last_name):
        if not first_name:
            return "invalid_firstname"
        if not last_name:
            return "invalid_lastname"  
        if User.objects(user_name=username):
            return "username_exists"
        if not email:
            return "invalid_email"
        elif not re.match("[^@]+@[^@]+\.[^@]+", email):
                return "invalid_email"
        if User.objects(email=email):
            return "email_exists"         
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
                return "Sorry, Please provide a valid email address"
            if User.objects(email=email):
                return "Sorry, This email is already registered"
            return True
        return False
    def validate_forgot_password_email(self,email):
        if email:
            if not re.match("[^@]+@[^@]+\.[^@]+", email):
                return "Sorry, This looks like an invalid email address"
            if User.objects(email=email):

                return True
            else:
                return "Sorry, The email provided is not a valid user email"
            return True
        return False    
    
    def validate_inactive_user_email(self,email):
        if email:
            if not re.match("[^@]+@[^@]+\.[^@]+", email):
                return "Sorry, This looks like an invalid email address"
            if User.objects(Q(email =email ) & Q(active= False)).first():

                return True
            else:
                return "Sorry, The email provided is not a valid user email"
            return True
        return False   
    def validate_sign_in(self,email,password,is_otp_verify=False):
        if email and password:
            user = User.objects(email=email).first()
            if user and sha256.verify(password, user.password) and user.active:
                return True
            elif  user and sha256.verify(password, user.password) and not user.active and  is_otp_verify:
                return True
            elif  user and sha256.verify(password, user.password) and not user.active and not is_otp_verify:
                return "Oops!,Your account is Inactive"
        return False
    
    def forgot_password_otp(self,req):
        if req:
            data = req.get('phone',False) or req.get('email',False)
            user =User.objects(Q(email =data ) | Q(phone= data)).first()
            if user and data:
                otp = randint(100000, 999999)
                user.otp = sha256.hash(str(otp))
                user.save()
                return True
            return False
        return False
    #================validate otp and make signup complete=====================    
    def validate_otp_for_signup(self,req):
        if req:
            data_otp = req.get('otp',False)
            data_email=req.get('email',False)
            data_phone=req.get('phone',False)
            
            user =User.objects((Q(phone= data_phone) | Q(email= data_email)) ).first()
            
            if user and not sha256.verify(str(data_otp), user.signup_otp):
                return False
            elif user and  user.signup_otp and sha256.verify(str(data_otp), user.signup_otp) and not user.active:
                user.active=True
                user.signup_otp=''
                user.save()
                return True
            else:
                return False
        return False 
    



    #=========================Update new Password======================================
    def validate_otp_and_update_new_password(self,req):
        if req:
            data_otp = req.get('otp',False)
            data_email=req.get('email',False)
            data_phone=req.get('phone',False)
            data_new_password=req.get('new_password',False)
            
            user =User.objects((Q(phone= data_phone) | Q(email= data_email)) ).first()
            if user and (sha256.verify(data_new_password, user.password) or not sha256.verify(str(data_otp), user.otp) ):
                return False
            elif user and data_new_password and user.otp and sha256.verify(str(data_otp), user.otp):
                user.password=sha256.hash(data_new_password)
                user.otp=''
                user.save()
                return True
            else:
                return False
        return False 
    #==========================Validation of otp expiry=========================== 
    def validate_otp_time_limit(self,email,purpose='forgot_password'):
        if email:
            user = User.objects(Q(email =email )).first()
            if user and user.signup_otp and purpose =='verify_signup':
                time_diff=datetime.datetime.utcnow()-user.last_signup_mail_sent
            
                if time_diff.days == 0 and (time_diff.seconds/60)<resend_password_time_limit :
                    return True
                else:
                    return False

            elif user and user.otp and purpose == 'forgot_password':
                time_diff=datetime.datetime.utcnow()-user.last_forgot_password_mail_sent
                
                
                if time_diff.days == 0 and (time_diff.seconds/60)<resend_password_time_limit :
                    return True
                else:
                    return False
            else:
                
                return False
        return False
       #==========================Validation of otp expiry=========================== 
    def validate_signup_otp_time_limit(self,email):
        if email:
            user = User.objects(Q(email =email )).first()
            
            if user and user.otp:
                time_diff=datetime.datetime.utcnow()-user.last_forgot_password_mail_sent
                
                
                if time_diff.days == 0 and (time_diff.seconds/60)<resend_password_time_limit :
                    return True
                else:
                    return False
            else:
                
                return False
        return False
    #==========================Send otp Mail on forgot password===========================
    def send_email_with_otp(self,email,mail_obj,executor,purpose='forgot_password'):
        try:
            if mail_obj:
                
                if email:
                    otp = randint(100000, 999999)
                    user = User.objects(Q(email =email )).first()
                    
                    msg = Message("REG:OTP Travellerspedia",
                    
                    recipients=[email])
                    if purpose == 'forgot_password':
                        user.otp = sha256.hash(str(otp))
                        user.last_forgot_password_mail_sent=datetime.datetime.utcnow()
                        user.save()
                        msg.html="<p>Hi,</p><br/>Please Use OTP:"+str(otp)+" for your forgot password request.<br/>Please note that the OTP expires in 5 minutes. <br/><br/><br/>Thanks,<br/>Travellerspedia Team" 
                    if purpose == 'verify_signup':
                        user.signup_otp = sha256.hash(str(otp))
                        
                        user.last_signup_mail_sent=datetime.datetime.utcnow()
                        user.save()
                        msg.html="<p>Hi,</p><br/>Please Use OTP:"+str(otp)+" for your signup request.<br/>Please note that the OTP expires in 5 minutes. <br/><br/><br/>Thanks,<br/>Travellerspedia Team" 
                    if executor:
                        future=executor.submit(send_mail,mail_obj,msg)
                        logging.info(future)
                    else:
                        
                        send_mail(mail_obj,msg)
                    return True
                else:
                    return False
        except Exception as e:  
            logging.error(e)
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
        # user = User.objects(id = claims.get('user_id'),active=True).first() if claims and  claims.get('user_id') else ''
        post = Post.objects(author=self,active=True).count()
        if self.active:
            return{'user_name':self.user_name,'name':str(self.first_name)+' '+str(self.last_name),'language':self.language,'profile_image':config['URL']+'/profile/'+str(self.id) if profile.profile_image_orginal else '','following':True if self in profile.followers else False,'id':str(self.id),'gender':self.gender or '','followers_count':len(profile.followers) if profile.followers else 0 ,'following_count':len(profile.following) if profile.following else 0,'no_of_post':post}
        return {'user_name':'in_active_user','name':'Inactive User','language':'en/US','profile_image':'','following':False,'id':'','gender':'','followers':0}
    
    def to_detail_json(self,claims=None):
        profile = Profile.objects(user= self).first()
        user = User.objects(id = claims.get('user_id'),active=True).first() if claims and  claims.get('user_id') else ''
        post = Post.objects(author=self,active=True).count()
        if self.active:
            return{'user_name':self.user_name,'name':str(self.first_name)+' '+str(self.last_name),'language':self.language,'profile_image':config['URL']+'/profile/'+str(self.id) if profile.profile_image_orginal else '','following':True if user in profile.followers else False,'id':str(self.id),'gender':self.gender or '','first_name':self.first_name,'last_name':self.last_name,'phone':self.phone if user in profile.followers or user == self else '','email':self.email if user in profile.followers or user == self else '','edit': True if user == self else False,'no_of_post':post,'followers_count':len(profile.followers),'following_count':len(profile.following)}
        return {'user_name':'in_active_user','name':'Inactive User','language':'en/US','profile_image':'','following':False,'id':'','gender':'','last_name':'','phone':'','email':'','edit': False,'no_of_post':post}
    
    def search(self,search,claims):
        if search.get('search') and claims:
            value = search.get('search')
            user =  claims.get('user_id')
            results = User.objects[:5].filter((Q(email =value) | Q(phone = value) | Q(user_name__istartswith = value) | Q(first_name__istartswith = value)) & Q(active = True))
            posts = Post.objects[:5](hashtags=search.get('search'),privacy='Public')
            return{'hashtag':[post.to_json(claims) for post in posts],'user':[res.to_json(claims) for res in results ]}
        return False
    
    def get_user(self,claims):
        if claims:
            return User.objects(id = claims.get('user_id'),active=True).first()
        return False
    
    def get_users(self,claims):
        if claims:
            users = User.objects(id__ne=claims.get('user_id'),active=True)
            return [user.to_json(claims) for user in users]
        return []

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
    active = BooleanField(default=False)
    signup_otp = StringField()
    last_forgot_password_mail_sent = DateTimeField()
    last_signup_mail_sent = DateTimeField()
    gender = StringField(default='')
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
    profile_crop_area= StringField()
    profile_image_file_name = StringField()


    def upload_image(self,req,claims):
        if req and claims and req.get('data'):
            author = User.objects(id=claims.get('user_id')).first()
            profile = Profile.objects(user= author).first()
            if not profile:
                profile = Profile(user=author).save()
            profile.profile_image_orginal=base64.b64decode(req.get('data'))
            if req.get('cropped'):
                profile.profile_image_small = base64.b64decode(req.get('cropped'))
            if req.get('crop_area'):
                profile.profile_crop_area = req.get('crop_area')
            profile.profile_image_file_name = req.get('file_name')+'.'+req.get('file_ext')
            profile.save()
            return {'code':200,'status':'Profile image uploaded successfully.'}
        return False

    def download_profile(self,user_id):
        user_id = User.objects(id =user_id,active=True).first()
        media = Profile.objects(user=user_id).first()
        if media:
            return {'filename': media.profile_image_file_name,'content':media.profile_image_orginal.read(),'crop':media.profile_image_small.read()}
        return False

    def follow_user(self,req,claims):
        if req and claims and req.get('user_id'):
            user = User.objects(id=claims.get('user_id')).first()
            follow_user = User.objects(id=req.get('user_id')).first()
            profile = Profile.objects(user=user).first()
            follow_profile = Profile.objects(user=follow_user).first()
            if user and follow_user and follow_user != user and follow_user not in profile.blocked_by:
                if follow_user not in profile.following and user not in follow_profile.followers:
                    profile.following.append(follow_user)
                    follow_profile.followers.append(user)
                    profile.save()
                    follow_profile.save()
                    return True
                else:
                    profile.following.remove(follow_user)
                    follow_profile.followers.remove(user)
                    profile.save()
                    follow_profile.save()
                    return True
            return False
        return False

    def block_user(self,req,claims):
        if req and claims and req.get('user_id'):
            user = User.objects(id=claims.get('user_id')).first()
            block_user = User.objects(id=req.get('user_id')).first()
            profile = Profile.objects(user=user).first()
            block_profile = Profile.objects(user=block_user).first()
            if user and block_user and block_user != user and block_user not in profile.blocklist:
                if block_user:
                    block_profile.blocked_by.append(user)
                    profile.followers.remove(block_user)
                    block_profile.following.remove(user)
                    profile.save()
                    block_profile.save()
                    return True
                return False
            return False
        return False
    
    def edit_profile(self,req,claims=None):
        if req and claims:
            user = User.objects(id=claims.get('user_id')).first()
            profile = Profile.objects(user=user).first()
            user.first_name = req.get('first_name')
            user.last_name = req.get('last_name')
            user.phone = req.get('phone')
            user.gender =req.get('gender')
            user.save()
            return user.to_json(claims)
        return False
    
    def view_profile(self,req,claims=None):
        if req and claims and req.get('user_id'):
            user = User.objects(id=claims.get('user_id')).first()
            profile_user = User.objects(id=req.get('user_id')).first()
            profile = Profile.objects(user=profile_user).first()
            if user and user not in profile.blocklist:
                return profile_user.to_detail_json(claims)
            return False
        return False
            
    def get_followers(self,req,claims={}):
        user_id = req.get('user_id') or claims.get('user_id')
        if user_id:
            user = User.objects(id=user_id).first()
            profile = Profile.objects(user=user).first()
            return [usr.to_detail_json(claims) for usr in profile.followers]
        return False

    def get_following(self,req,claims={}):
        user_id = req.get('user_id') or claims.get('user_id')
        if user_id:
            user = User.objects(id=user_id).first()
            profile = Profile.objects(user=user).first()
            return [usr.to_detail_json(claims) for usr in profile.following]
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
        return config['URL']+'/media/'+str(self.id)

    def download_media(self,media_id):
        media = MediaAttachment.objects(id=media_id).first()
        if media:
            return {'filename': media.filename,'content':media.content.read()}
        return False

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
            if comment and comment.user == user:
                    comment.active=False
                    comment.save()
                    activity=UserActivity()
                    activity.add_activity(data={'user_id':claims.get('user_id'),'action':'remove','comment_id':comment.id})
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
                    activity=UserActivity()
                    # activity.add_activity(data={'user_id':claims.get('user_id'),'action':'like','comment_id':commment_id})
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
                    activity=UserActivity()
                    # activity.add_activity(data={'user_id':claims.get('user_id'),'action':'dislike','comment_id':req.get('comment')})
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
                comment = Comment(comment=req.get('comment'),user= user,attachments=attachment,mentions=mention,hashtags = re.findall(r"#(\w+)",req.get('comment')))
                comment.save()
                post.comments.append(comment)
                post.save()
                activity=UserActivity()
                activity.add_activity(data={'user_id':claims.get('user_id'),'post_id':post.id,'action':'add','comment_id':comment.id})
                return {"code":200,"status":"Success","comment":comment.to_json(claims)}
            return False
        return False

    def edit_comment(self,req,claims):
        if req.get('comment') and req.get('comment_id') and claims:
            attachment =[]
            mention=[]
            user = User.get_user(self,claims=claims)
            comment = Comment.objects(active=True,id=req.get('comment_id')).first()
            if user and comment:
                for media in req.get('attachments',[]):
                    m = MediaAttachment(filename=media.get('file_name'),file_extension=media.get('file_ext'),type=media.get('file_type'),content=base64.b64decode(media.get('data')),uploaded_by=author).save()
                    attachment.append(m)
                for user in req.get('mention',[]):
                    u = User.objects(id=user)
                    mention.append(u)
                comment.comment = req.get('comment')
                comment.attachments = attachment
                comment.mentions = mention
                comment.hashtags = re.findall(r"#(\w+)",req.get('comment'))
                comment.save()
                activity=UserActivity()
                activity.add_activity(data={'user_id':claims.get('user_id'),'action':'update','comment_id':comment.id})
                return comment.to_json(claims)
            return False
        return False

    def to_json(self,claims):
        if self.active:
            user= User.get_user(self,claims=claims)
            likes_by=[user.to_json() for user in self.liked_by[:limit]]
            dislikes_by=[user.to_json() for user in self.disliked_by[:limit]]
            attachments=[attachment.to_json() for attachment in self.attachments[:limit]]
            liked = True if claims and user in self.liked_by else False
            disliked = True if claims and user in self.disliked_by  else False
            data={'id':str(self.id),'author':self.user.to_json(claims),'created_on':self.created_time,'updated_on':self.updated_time,'comment':self.comment,'likes':len(self.liked_by),'liked_by':likes_by,'dislikes':len(self.disliked_by),'disliked_by':dislikes_by,'hashtags':self.hashtags,'attachments':attachments,'liked':liked,'dislike':disliked,'owner':True if self.user== user else False}
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
    location = GeoPointField(default=[])
    
    def to_json(self,claims=None):
        if self.active:
            user= User.objects(active=True,id=claims.get('user_id')).first()
            likes_by=[user.to_json(claims) for user in self.liked_by[:limit]]
            dislikes_by=[user.to_json(claims) for user in self.disliked_by[:limit]]
            attachments=[attachment.to_json() for attachment in self.attachments[:limit]]
            comments=[comment.to_json(claims)for v,comment in enumerate(self.comments) if comment.active and v < limit]
            liked = True if claims and user in self.liked_by else False
            disliked = True if claims and user in self.disliked_by  else False
            collections = Collections.objects(active=True,user=claims.get('user_id')).first()
            if collections and self in collections.posts:
                    # logging.info(data.to_json(claims))
                collection =True
            else:
                collection =False
            data={'id':str(self.id),'author':self.author.to_json(claims),'created_on':self.created_time,'updated_on':self.updated_time,'post':self.post,'topic':self.topic,'likes':len(self.liked_by),'liked_by':likes_by,'dislikes':len(self.disliked_by),'disliked_by':dislikes_by,'shares':self.shares,'privacy':self.privacy,'hashtags':self.hashtags,'attachments':attachments,'liked':liked,'dislike':disliked,'comments':comments,'owner':True if self.author==user else False,'location':self.location,'collection': collection}
            return data

    def to_data(self,claims=None):
        if self.active:
            user= User.objects(active=True,id=claims.get('user_id')).first()
            likes_by=[user.to_json(claims) for user in self.liked_by[:limit]]
            dislikes_by=[user.to_json(claims) for user in self.disliked_by[:limit]]
            attachments=[attachment.to_json() for attachment in self.attachments[:limit]]
            comments=[comment.to_json(claims)for v,comment in enumerate(self.comments) if comment.active and v < limit]
            liked = True if claims and user in self.liked_by else False
            disliked = True if claims and user in self.disliked_by  else False
            collections = Collections.objects(active=True,user=claims.get('user_id')).first()
            if collections and self in collections.posts:
                    # logging.info(data.to_json(claims))
                collection =True
            else:
                collection =False
            data={'id':str(self.id),'author':self.author.to_json(claims),'created_on':self.created_time,'updated_on':self.updated_time,'post':self.post,'topic':self.topic,'likes':len(self.liked_by),'liked_by':likes_by,'dislikes':len(self.disliked_by),'disliked_by':dislikes_by,'shares':self.shares,'privacy':self.privacy,'hashtags':self.hashtags,'attachments':attachments,'liked':liked or 0,'dislike':disliked or 0,'comments':comments,'total_comments':len(comments) if len(comments) else 0,'owner':True if self.author==user else False,'location':self.location,'collection': collection}
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
            
            new_post =Post(author=author,post=post['post'],topic=post.get('topic'),privacy=post.get('privacy'),attachments=attachment,mentions=mention,hashtags=re.findall(r"#(\w+)", post.get('post')),location=post.get('location',[]))
            return new_post.save().to_json(claims)
        return False
    
    def get_my_post(self,data,claims):
        if claims and data:
            skip_count = int(data.get('skip_count',0))
            # author = User.objects(id=claims['user_id']).first()
            posts =Post.objects(active=True,privacy='Public',author=claims['user_id']).order_by('-created_time').skip(skip_count).limit(int(posts_view_threshold)+skip_count)
            if posts:
                return [post.to_json(claims) for post in posts ]
        return False
    def edit_post(self,post_id,post,claims):
        if post_id:
            post_obj =Post.objects(active=True,id=post_id,privacy='Public').first()
            if post_obj:
                attachment =[]
                mention=[]
                author = User.objects(id=claims['user_id']).first()
                for media in post.get('attachments',[]):
                    m = MediaAttachment(filename=media.get('file_name'),file_extension=media.get('file_ext'),type=media.get('file_type'),content=base64.b64decode(media.get('data')),uploaded_by=author).save()
                    attachment.append(m)
                for user in post.get('mention',[]):
                    u = User.objects(id=user)
                    mention.append(u)
                post_obj.post=post.get('post')
                post_obj.topic=post.get('topic')
                post_obj.privacy=post.get('privacy')
                post_obj.attachments=attachment
                post_obj.mentions=mention
                post_obj.created_time=post_obj.created_time
                post_obj.hashtags=re.findall(r"#(\w+)", post.get('post'))
                post_obj.updated_time = datetime.datetime.now()
                post_obj.save()
                return post_obj.to_json(claims)
            return False
        return False
    
    def view_post(self,post_id,claims):
        if post_id:
            post =Post.objects(active=True,id=post_id,privacy='Public').first()
            if post and post.active:
                return post.to_json(claims)
            return False
        return False
    
    def get_reacts_around(self,data,claims):
        if data and 'location' in data and claims:
            location = data.get('location',False)
            distance = int(data.get('location_max_distance',0)) if int(data.get('location_max_distance',0)) else 10
            final_data = []
            if location and distance:                
                posts =Post.objects(active=True,privacy='Public',location__within_spherical_distance =(location,distance/6371)).order_by('-updated_time').limit(10)
                # print(len(posts),"======>no of posts")
                if len(posts)>0:
                    post_data = [post.to_data(claims) for post in posts]
                    # print(len(post_data),"======>no of post_data")
                    if len(post_data)>0:
                        post_data.sort(key=lambda x: x.get('total_comments',0))
                        # print(len(post_data),"======>no of post_data comments sorted")
                        final_data.append(post_data[0])
                        post_data.pop(0)
                    if len(post_data)>0:
                        post_data.sort(key=lambda x: x.get('liked',0))
                        final_data.append(post_data[0])
                        post_data.pop(0)
                    if len(post_data)>0:
                        post_data.sort(key=lambda x: x.get('disliked',0) ,reverse=True)
                        final_data.append(post_data[0])
                        post_data.pop(0)
                    # print(len(post_data),"======>no of post_data")
                    if len(post_data)>0:
                        post_data.sort(key=lambda x: x.get('updated_on',0),reverse=True)
                        final_data.extend(post_data)
            if len(final_data):
                return final_data

        return False
    
    def view_all_post(self,data,claims):
        if claims:
            skip_count = int(data.get('skip_count',0))
            location = data.get('location',False)
            distance = int(data.get('location_max_distance',0)) if int(data.get('location_max_distance',0)) else 10
            
            if location and distance:
                
                posts =Post.objects(active=True,privacy='Public',location__within_spherical_distance =(location,distance/6371)).order_by('-updated_time').skip(skip_count).limit(int(posts_view_threshold)+skip_count)
            else:
                posts =Post.objects(active=True,privacy='Public').order_by('-updated_time').skip(skip_count).limit(int(posts_view_threshold)+skip_count)
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
                    activity=UserActivity()
                    activity.add_activity(data={'user_id':claims.get('user_id'),'post_id':posts.id,'action':'like'})
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
                    activity=UserActivity()
                    activity.add_activity(data={'user_id':claims.get('user_id'),'post_id':posts.id,'action':'dislike'})
                    return True
                else:
                    posts.liked_by.remove(user) if user in posts.liked_by else False
                    posts.disliked_by.remove(user)
                    posts.save()
                    return True
                return False
            return False
        return False

    def get_post_hashtag(self,tag,claims):
        if tag and claims:
            posts =Post.objects(active=True,hashtags=tag)
            return [post.to_json(claims) for post in posts]
        return False
    
    def view_near_by(self,req,claims):
        location =[]
        if req.get('location') and claims:
            location = req.get('location')
        elif req.get('post') and claims:
            post = Post.objects(id=req.get('post'),active=True).first()
            location = post.location
        distance = int(req.get('radius',0)) if int(req.get('radius',0)) else 10

        if location:
            posts = Post.objects[:20](active=True,privacy='Public',location__within_spherical_distance=(location,distance/6371))
            return [post.to_json(claims) for post in posts]
        return []    
            


class Collections(Document):
    user = ReferenceField(User,required=True)
    posts =ListField(ReferenceField(Post))
    created_time= DateTimeField(default=datetime.datetime.now(),required=True)
    updated_time= DateTimeField(default=datetime.datetime.now())
    active = BooleanField(default=True)

    def add_to_collections(self,data,claims):
        if data and claims.get('user_id',False):
            my_collections=Collections.objects(active=True,user=claims.get('user_id')).first()
            post=Post.objects(id=data.get('post_id')).first()
            
            # logging.info(Post.objects(id=data.get('post_id')).to_json())
            if my_collections:
                collection_list=list(set(my_collections.posts))
                collection_list.append(post)
                my_collections.posts=collection_list
                my_collections.updated_time=datetime.datetime.now()
                
            else:
                user=claims.get('user_id')
                posts=[post]
                my_collections=Collections(user=user,posts=posts)
            
            my_collections.save()
            activity=UserActivity()
            activity.add_activity(data={'user_id':claims.get('user_id'),'post_id':post.id,'action':'add','collection_id':my_collections.id})
            # logging.info(my_collections.to_json(claims))
            return True
        else:
            return False
    
    def remove_from_collections(self,data,claims):
        if data and claims.get('user_id',False):
            my_collections=Collections.objects(active=True,user=claims.get('user_id')).first()
            if my_collections:
                post=Post.objects(id=data['post_id'],active=True).first()
                if post:
                    # logging.info(post.to_json(claims))
                    my_collections.posts.remove(post)
                    my_collections.updated_time=datetime.datetime.now()
                    my_collections.save()
                    activity=UserActivity()
                    activity.add_activity(data={'user_id':claims.get('user_id'),'post_id':post.id,'action':'remove','collection_id':my_collections.id})
                    
                    return True
            return False
        else:
            return False

    def get_my_collections(self,data,claims):
        if claims.get('user_id',False):
            skip_count = int(data.get('skip_count',0))
            my_collections=Collections.objects(active=True,user=claims.get('user_id')).fields(slice__posts=[skip_count,int(posts_view_threshold)+skip_count]).first()
            if my_collections:            
                return my_collections.to_json(claims)
        return []
    
    def to_json(self,claims):
        if self.active and claims:
            user= User.get_user(self,claims=claims)
            my_posts=[post.to_json(claims) for post in set(self.posts) if post.active]
            
            data={'user':self.user.to_json(claims),'created_on':self.created_time,'updated_on':self.updated_time,'posts':my_posts}
            return data
        return False


class UserActivity(Document):
    user = ReferenceField(User,required=True)
    description = StringField(required=True,default='')
    post_id = ReferenceField(Post)
    collection_id = ReferenceField(Collections)
    comment_id = ReferenceField(Comment)
    profile_id = ReferenceField(Profile)
    media_id = ReferenceField(MediaAttachment)
    created_time = DateTimeField(default=datetime.datetime.now(),required=True)
    updated_time = DateTimeField(default=datetime.datetime.now())
    action = StringField(required=True,default='')
    active = BooleanField(default=True)

    def add_activity(self,data):
        activity_count = UserActivity.objects(active=True,user=data.get('user_id')).count()
        if activity_count < activity_threshold:
            activity=UserActivity()
        else:
            activity = UserActivity.objects(user=data.get('user_id'),active=True).skip(19)
            if activity:
                activity=activity[0]
        if data and data.get('user_id',None):

            user=data.get('user_id',None)
            post=data.get('post_id',None)
            collection=data.get('collection_id',None)
            comment=data.get('comment_id',None)
            action=data.get('action',None)
            description=None
            
            if user and post and collection and action:
                user=User.objects(id = data.get('user_id'),active=True).first()
                post=Post.objects(id = data.get('post_id'),active=True).first()
                collection=Collections.objects(id = data.get('collection_id'),active=True).first()
                user_name= str(user.first_name)+''+str(user.last_name) if user.first_name and user.last_name else str(user.first_name)
                if user and post and collection  and action=='add':
                    description = user_name+' have added '+str(post.topic)+' to collection'
                if user and post and collection  and action=='remove':
                    description = user_name+' have removed '+str(post.topic)+' from collection'
                if description:
                    activity.user=user
                    activity.post_id=post
                    activity.collection_id=collection
                    activity.description=description
                    activity.action=action
                    activity.updated_time=datetime.datetime.now()
                    activity.save()
                    # logging.info(activity.to_json())
                    return True
            
            elif user and comment and action :
                
                user=User.objects(id = data.get('user_id'),active=True).first()
                comment =Comment.objects(active=True,id=comment).first()
                post=Post.objects(comments__in=[comment], active=True).first()
                user_name = str(user.first_name) + '' + str(
                    user.last_name) if user.first_name and user.last_name else str(user.first_name)
                if user and post and comment  and action=='add':
                    description = str(user_name)+' have commented on '+str(post.topic)
                if user and post and comment  and action=='remove':
                    description = str(user_name)+' have removed the comment from '+str(post.topic)
                if user and post and comment  and action=='update':
                    description = str(user_name)+' have edited the comment on '+str(post.topic)
                # if user and comment and action=='like':
                #     description = str(user.profile_name)+' liked the your comment '
                # if user and comment  and action=='dislike':
                #     description = str(user.profile_name)+' disliked your comment '
                if description:
                    activity.user=user if user else None
                    activity.post_id=post if post else None
                    activity.comment_id=comment if comment else None
                    activity.description=description
                    activity.action=action
                    activity.updated_time=datetime.datetime.now()
                    activity.save()
                    # logging.info(activity.to_json())
                    return True

            elif user and post and action and action in ['like','dislike']:
                user=User.objects(id = data.get('user_id'),active=True).first()
                post=Post.objects(id = data.get('post_id'),active=True).first()
                user_name = str(user.first_name) + '' + str(
                    user.last_name) if user.first_name and user.last_name else str(user.first_name)
                if user and post and action=='like':
                    description = str(user_name)+' liked '+str(post.topic)
                if user and post and action=='dislike':
                    description = str(user_name)+' disliked '+str(post.topic)
                if description:
                    activity.user=user
                    activity.post_id=post
                    activity.description=description
                    activity.action=action
                    activity.updated_time=datetime.datetime.now()
                    activity.save()
                    # logging.info(activity.to_json())
                    return True
            
            return False
    def get_my_activity(self,claims):
        activity=UserActivity.objects(user=claims.get('user_id'),active=True).order_by('-updated_time')     

        my_activities=[]
        for act in activity:
            my_activities.append({
                'user':act.user.to_json(claims),
                'description':act.description,
				'id':str(act.id),
                'updated_time':act.updated_time,
                'post_id':str(act.post_id.id) if act.post_id else '',
                'collection_id':str(act.collection_id.id) if act.collection_id else ''
                
            })

        if my_activities:
            return my_activities
        else:
            return False
    
    def delete_my_activity(self,claims,data=None):
        if claims and isinstance(data,dict):
            activity_id=data.get('activity_id',None)
            activity=UserActivity.objects(id=activity_id,user=claims.get('user_id'),active=True).first()
            if activity:
                activity.active=False
                activity.save()
                return True
            else:
                return False
        elif claims and data=='all':
            activity=UserActivity.objects(user=claims.get('user_id'),active=True)
            for act in activity:
                act.active=False
                act.save()
            return True
        else:
            return False


class Message(Document):
    reference_message = ReferenceField('self')
    time = DateTimeField(default= datetime.datetime.utcnow())
    message = StringField()
    delivered = BooleanField(default=False)
    viewed = BooleanField(default=False)
    active = BooleanField(default=True)
    attachments = ListField(ReferenceField(MediaAttachment))


class MessageGroup(Document):
    participants = ListField(ReferenceField(User,required=True))
    active = BooleanField(default=True)
    messages = ListField(ReferenceField(Message))


def send_mail(mail_obj,msg):
    try:
        mail_obj.send(msg)
        return True
    except Exception as error :
        logging.error(error)
        return False     