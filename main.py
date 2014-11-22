import os
import webapp2
import jinja2
from collections import namedtuple
from google.appengine.ext import db
import hmac
import hashlib

import string
import random

import re
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile("^.{3,20}$")
EMAIL_RE = re.compile("^[\S]+@[\S]+\.[\S]+$")

def valid_username(username):
    return USER_RE.match(username)
def valid_password(password):
    return USER_RE.match(password)
def valid_email(email):
    return USER_RE.match(email)

SECRET = "imsosecret"
def hash_str(s):
    return hmac.new(SECRET,s).hexdigest()
def make_secure_val(s):
    return "%s|%s"%(s,hash_str(s))
def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val

    
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),autoescape = True)

class Handler(webapp2.RequestHandler):
    def write(self,*a,**kw):
        self.response.out.write(*a,**kw)
    
    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)
    
    def render(self,template,**kw):
        self.write(self.render_str(template, **kw))

class Posts(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add=True)


def make_salt(length=5):
    return ''.join([random.choice(string.letters) for i in xrange(5)])

def make_pw_hash(name,pw,salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name+pw+salt)

def users_key(group='default'):
    return db.Key.from_path('users',group)



class User(db.Model):
    username = db.StringProperty(required = True)
    password_hash = db.StringProperty(required = True)
    email = db.StringProperty()
    
    @classmethod
    def by_name(cls,name):
        return User.all().filter('username=',name).get()
    
    @classmethod
    def by_id(cls,uid):
        return User.get_by_id(uid, parent=users_key())
    
    @classmethod
    def register(cls,name,pw,email=None):
        pw_hash = make_pw_hash(name,pw)
        return User(parent=users_key(),
                    username=name,password_hash=pw_hash,
                    email=email)
    
    
    
        
class MainPage(Handler):
    def get(self):
        self.render("login.html")

class CookiesHandler(Handler):
    def get(self):
        self.response.headers['Content-Type'] = 'text/plain'
        visits = 0
        visit_cookie_str = self.request.cookies.get('visits')
        if visit_cookie_str:
            cookie_val = check_secure_val(visit_cookie_str)
            if cookie_val:
                visits = int(cookie_val)
        visits += 1
        new_cookie_val = make_secure_val(str(visits))
        self.response.headers.add_header('Set-Cookie', 'visits=%s'%new_cookie_val)
        if visits > 100:
            self.write("You are best ever!")
        else:
            self.write("You've been here %s times!"%visits)
class NewPostHandler(Handler):
    def render_front(self,subject="",content="",error=""):
        self.render("create.html",subject=subject,content=content,error=error)
    
    def get(self):
        self.render_front()
    
    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")
        
        if subject and content:
            p = Posts(subject=subject,content=content)
            p.put()
            
            self.redirect("/blog/%s"%p.key().id())
        else:
            self.render_front(subject,content,error="We need both a subject and some content")
        
class FrontPageHandler(Handler):
    def render_front(self,title="",art="",error=""):
        posts = db.GqlQuery("SELECT * FROM Posts " + 
                           "ORDER BY created DESC ")
        
        self.render("front.html",posts=posts)
    def get(self):
        self.render_front()

class PermalinkHandler(Handler):
    def get(self,post_id):
        mypost = Posts.get_by_id(int(post_id))
        if mypost:
            self.render("permalink.html",mypost=mypost)
        else:
            self.redirect('/blog')

class SignUpHandler(Handler):
    def get(self):
        self.render("register.html")
    def post(self):
        values = {}
        iferror = False
        username = self.request.get("username")
        password = self.request.get("password")
        verify = self.request.get("verify")
        email = self.request.get("email")
        
        if not (username and valid_username(username)):
            values['username_error']="invalid username"
            iferror = True
        else:
            values['username'] = username
        
        if not (password and valid_password(password)):
            values['password_error']="invalid password"
            iferror = True
        elif password != verify:
            values['verify_error']="invalid verify"
            iferror = True
        
        if email:
            if not valid_email(email):
                values['email_error']="invalid email"
            else:
                values['email']=email
        
        if iferror:
            self.render("register.html",**values)
        else:
            self.write("good!")
            
app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/blog',FrontPageHandler),
    ('/blog/newpost',NewPostHandler),
    ('/blog/(\d+)',PermalinkHandler),
    ('/c',CookiesHandler),
    ('/signup',SignUpHandler)
], debug=True)
