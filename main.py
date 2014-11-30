import os
import re
import random
import hashlib
import hmac
from string import letters
import time
import webapp2
import jinja2

from google.appengine.ext import db


# directory for templates
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)
# secret for password hash
secret = 'fart'


def datetimeformat(value, format='%H:%M / %d-%m-%Y'):
    return value.strftime(format)
jinja_env.filters['datetimeformat'] = datetimeformat
# HELPING FUNCTIONS

# secure value for cookie


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


# functions for sign up
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)


# user stuff
def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


def users_key(group='default'):
    return db.Key.from_path('users', group)

# for blog


def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)


def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


# DATA BASE

class User(db.Model):
    username = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()
    status = db.StringProperty()
    about = db.StringProperty()
    male = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add=True)

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('username =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None, status=None, about=None, male=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    username=name,
                    pw_hash=pw_hash,
                    email=email,
                    status=status,
                    about=about,
                    male=male)

    @classmethod
    def get_posts_number(cls, username):
        return Post.all().filter('username =', username).count()

    @classmethod
    def get_likes_number(cls, username):
        posts = Post.by_username(username)
        return sum([a.likes for a in posts])

    @classmethod
    def get_comments_number(cls, username):
        comments = Post.by_username(username)
        return sum([a.comments for a in comments])

    @classmethod
    def get_views_number(cls, username):
        views = Post.by_username(username)
        return sum([a.views for a in views])

    @classmethod
    def get_following_posts(cls, username):
        f = Followers.get_followings(username)
        if f:
            posts = []
            for i in f:
                posts_temp = Post.by_username(username)
                for j in posts_temp:
                    posts.append(j)
            posts = sorted(
                posts, key=lambda post: post.created)
            posts = [posts[i] for i in xrange(len(posts) - 1, -1, -1)]
            return posts
        else:
            return None

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


class Post(db.Model):
    user = db.StringProperty(required=True)
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    likes = db.IntegerProperty()
    views = db.IntegerProperty()
    comments = db.IntegerProperty()

    @classmethod
    def by_id(cls, pid):
        return Post.get_by_id(pid, parent=blog_key())

    @classmethod
    def by_username(cls, username):
        posts = Post.all().filter('user= ', username)
        return posts

    @classmethod
    def get_by_followings(cls, followings):
        posts = []
        for i in followings:
            p = Post.all().filter('user =', i.username)
            for j in p:
                posts.append(j)
        posts = sorted(
            posts, key=lambda post: post.created)
        posts = [posts[i] for i in xrange(len(posts) - 1, -1, -1)]
        return posts

    @classmethod
    def new_post(cls, user, subject, content):
        p = Post(user=user, subject=subject, content=content,
                 likes=0, views=0, comments=0)
        return p

    def render(self, user, preview=False):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self, user=user)

    def if_liked(self, user):
        return Likes.if_liked(user, str(self.key().id()))


class Comments(db.Model):
    username = db.StringProperty(required=True)
    post_id = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

    @classmethod
    def by_post_id(cls, post_id):
        u = Comments.all().filter('post_id =', post_id).order('created')
        return u


class Likes(db.Model):
    username = db.StringProperty(required=True)
    post_id = db.StringProperty(required=True)
    time_liked = db.DateTimeProperty(auto_now_add=True)

    @classmethod
    def get_like(cls, username, post_id):
        l = Likes.all().filter('username =', username).filter(
            'post_id =', post_id).get()
        return l

    @classmethod
    def if_liked(cls, username, post_id):
        if Likes.all().filter('username =', username).filter('post_id =', post_id).get():
            return True
        else:
            return False


class Followers(db.Model):
    username = db.StringProperty(required=True)
    following_name = db.StringProperty(required=True)
    following_time = db.DateTimeProperty(auto_now_add=True)

    @classmethod
    def get_followers(cls, username):
        followers_name = Followers.all().filter('following_name =', username)
        if followers_name:
            followers = []
            for i in followers_name:
                f = i.username
                u = User.all().filter('username =', f).get()
                followers.append(u)
            return followers
        else:
            return None

    @classmethod
    def get_followings(cls, username):
        follwings_name = Followers.all().filter('username =', username)
        if follwings_name:
            followings = []
            for i in follwings_name:
                f = i.following_name
                u = User.all().filter('username =', f).get()
                followings.append(u)
            return followings
        else:
            return None

    @classmethod
    def if_following(cls, username, following_name):
        if Followers.all().filter('username =',
                                  username).filter('following_name =', following_name).get():
            return True
        else:
            return False
# HANDLERS

# base class for handlers


class BlogHandler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def like_btn(self, p, my_post):
        p = p
        my_post = my_post
        if Likes.if_liked(self.user.username, p):

            like = Likes.get_like(self.user.username, p)
            like.delete()

            my_post.likes = my_post.likes - 1
            my_post.put()

            time.sleep(0.1)
            self.redirect('/noize')
        else:
            l = Likes(username=self.user.username,
                      post_id=p)
            l.put()
            my_post.likes = my_post.likes + 1
            my_post.put()

    def follow_btn(self, following_name):
        following_name = following_name
        username = self.user.username
        if Followers.if_following(username, following_name):
            f = Followers.get_followings(username).filter(
                'following_name =', following_name)
            f.delete()
        else:
            f = Followers(username=username, following_name=following_name)
            f.put()

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


class MainPage(BlogHandler):

    def get(self):
        self.render('index.html')


class Signup(BlogHandler):

    def get(self):
        self.render("register.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('register.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class Register(Signup):

    def done(self):
        # make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('register.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/myposts')


class Login(BlogHandler):

    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/myposts')
        else:
            msg = 'Invalid login'
            self.render('login.html', error=msg)


class Logout(BlogHandler):

    def get(self):
        self.logout()
        self.redirect('/login')


class MyPosts(BlogHandler):

    def get(self):
        if self.user:
            posts = Post.all().filter('user =', self.user.username)
            self.render('front.html', posts=posts, forJS="my-posts")
        else:
            self.redirect('/login')

    def post(self):
        p = self.request.get('like')
        my_post = Post.get_by_id(int(p))
        self.like_btn(p, my_post)

        time.sleep(0.1)
        self.redirect('/myposts')


class Noize(BlogHandler):

    def get(self):
        if self.user:
            posts = Post.all().order('-created')
            self.render('front.html', posts=posts, forJS="noize")
        else:
            self.redirect('/login')

    def post(self):
        p = self.request.get('like')
        my_post = Post.get_by_id(int(p))
        self.like_btn(p, my_post)

        time.sleep(0.1)
        self.redirect('/noize')


class TopPosts(BlogHandler):

    def get(self):
        if self.user:
            posts = Post.all().order('-created')
            posts = sorted(
                posts, key=lambda post: (post.likes * 15) + post.views)
            posts = [posts[i] for i in xrange(len(posts) - 1, -1, -1)]
            self.render('front.html', posts=posts, forJS="top-posts")
        else:
            self.redirect('/login')

    def post(self):
        p = self.request.get('like')
        my_post = Post.get_by_id(int(p))
        self.like_btn(p, my_post)

        time.sleep(0.1)
        self.redirect('/top')


class LikedPosts(BlogHandler):

    def get(self):
        if self.user:
            likes = Likes.all().filter(
                'username =', self.user.username).order('-time_liked')
            l = [long(i.post_id) for i in likes]
            posts = [Post.get_by_id(i) for i in l]
            self.render('front.html', posts=posts, forJS="liked")
        else:
            self.redirect('/login')

    def post(self):
        p = self.request.get('like')
        my_post = Post.get_by_id(int(p))
        self.like_btn(p, my_post)

        time.sleep(0.1)
        self.redirect('/liked')


class PostPage(BlogHandler):

    def get(self, post_id):
        if self.user:
            # mpost = Post.by_id(int(post_id)
            #key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            #mpost = db.get(key)
            post = Post.get_by_id(int(post_id))
            post.views = post.views + 1
            post.put()
            comments = Comments.by_post_id(post_id)

            if not post:
                self.error(404)
                return
            else:
                self.render("permalink.html", post=post, comments=comments)
        else:
            self.redirect('/login')

    def post(self, post_id):
        if self.request.get('like'):
            p = self.request.get('like')
            my_post = Post.get_by_id(int(p))
            self.like_btn(p, my_post)

            time.sleep(0.1)
            self.redirect('/post/%s' % post_id)

        if self.request.get('comment'):
            uname = self.user.username
            p_id = post_id
            content = self.request.get('comment')

            if content:
                c = Comments(parent=blog_key(), username=uname,
                             post_id=p_id, content=content)
                c.put()
            self.redirect('/post/%s' % post_id)


class NewPost(BlogHandler):

    def get(self):
        if self.user:
            self.render("newpost.html", forJS="newpost")
        else:
            self.redirect("/login")

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content and len(subject) < 300 and len(content) < 2000:
            p = Post.new_post(self.user.username, subject, content)
            p.parent = blog_key()
            p.put()
            self.redirect('/post/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render(
                "newpost.html", subject=subject, content=content, error=error)


class UserPage(BlogHandler):

    def get(self, username):
        if self.user:
            if User.by_name(username):
                posts = Post.all().filter("user =", username)
                btn = ""
                if Followers.if_following(self.user.username, username):
                    btn = "unfollow"
                else:
                    btn = "follow"
                self.render('front2.html', posts=posts, username=username,
                            btn_name=btn)
            else:
                self.redirect('/myposts')
        else:
            self.redirect('/login')

    def post(self, username):
        following_name = self.request.get('username')
        if User.by_name(following_name):
            if Followers.if_following(self.user.username, username):
                f = Followers.all().filter('username =', self.user.username).filter(
                    'following_name =', following_name).get()
                f.delete()
                time.sleep(0.1)
                self.redirect('/userpage/%s' % username)
            else:
                f = Followers(
                    username=self.user.username, following_name=following_name)
                f.put()
                time.sleep(0.1)
                self.redirect('/userpage/%s' % username)


class NewsPage(BlogHandler):

    def get(self):
        followings = Followers.get_followings(self.user.username)
        posts = Post.get_by_followings(followings)
        self.render('front.html', posts=posts)

app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/signup', Register),
    ('/login', Login),
    ('/logout', Logout),
    ('/post/([0-9]+)', PostPage),
    ('/newpost', NewPost),
    ('/myposts', MyPosts),
    ('/noize', Noize),
    ('/top', TopPosts),
    ('/liked', LikedPosts),
    ('/userpage/(.*)', UserPage),
    ('/news', NewsPage)
], debug=True)
