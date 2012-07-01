#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import os, webapp2, jinja2, re, random, string, hashlib, datetime

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape=True)
    
class User(db.Model):
    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add = True)

class Task(db.Model):
    userid = db.IntegerProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    tname = db.StringProperty(required = True)
    tdesc = db.TextProperty()
    deadline = db.DateProperty()
    importance = db.IntegerProperty()
    parentid = db.IntegerProperty() #needs a default value of None/null
    # to add - a "done" marker that will show whether or not each task is done. default is "no"

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a,**kw)
    def render_str(self,template,**params):
        t = jinja_env.get_template(template)
        return t.render(params)
    def render(self,template,**kw):
        self.write(self.render_str(template,**kw))
    def make_salt(self):
        return ''.join(random.choice(string.letters) for x in xrange(5))
    def make_pw_hash(self,name,pw,salt=None):
        if not salt:
            salt = self.make_salt()
        hash_str = ''.join([name,pw,salt])
        newhash = hashlib.sha256(hash_str).hexdigest()
        return "%s|%s" %(newhash, salt)
    def hash_id_cookie(self,id):
        return '|'.join([str(id),hashlib.sha256(str(id)).hexdigest()])
    def valid_id_cookie(self,hash):
        if hash:
            id_no = int(hash.split('|')[0])
            if self.hash_id_cookie(id_no) == hash:
                return id_no
        return False
    def get_user(self,id_no):
        return User.get_by_id(id_no)
    def valid_user(self):
        id_cookie = self.request.cookies.get("id",0)
        id_no = self.valid_id_cookie(id_cookie)
        if id_no:
            return self.get_user(id_no)
        return None
        
class MainPage(Handler):
    def render_main_page(self):
        self.render("main.html")
    def get(self):
        self.render_main_page()
        u = self.valid_user()
        if u:
            self.write("Welcome, %s!<br>" % u.username)
            self.write("<a href='/newtask'>Add a new task.</a>")
        else:
            self.write("Please <a href='/login'>log in</a> or <a href='/signup'>sigh up</a>.")
   
class RegisterPage(Handler):
    def render_form(self,populate={'username': '', 'email': '', 'name_error': '', 'pass_error': '', 'verify_error': '', 'email_error': ''}):
        self.render("register.html", populate=populate)
        
    def valid_username(self,username):
        if re.match(r"^[a-zA-Z0-9_-]{3,20}$",username):
            return True
        return False
        
    def valid_password(self,password):
        if re.match(r"^.{3,20}$",password):
            return True
        return False
        
    def valid_email(self,email):
        if re.match(r"^[\S]+@[\S]+\.[\S]+$",email) or email == '':
            return True
        return False
        
    def match_password(self,password,verify):
        if password == verify:
            return True
        return False
        
    def no_dupe_name(self,username,dupes):
        if len(dupes) != 0:
            return False
        return True    
    
    def validate_form(self,username,password,verify,email,record):
        if self.valid_username(username) and self.valid_password(password) and self.valid_email(email) and self.match_password(password,verify) and self.no_dupe_name(username,record):
            return True
        return False
        
    def get(self):
        self.render_form()

    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")
        verify = self.request.get("verify")
        email = self.request.get("email")
        dupe_record = db.GqlQuery("SELECT * FROM User WHERE username='%s'" % username)
        recs = []
        for record in dupe_record:
            recs.append(record)
        dupe_name_error = '' if len(recs) == 0 else "That username is not available."
        name_error = '' if self.valid_username(username) else 'That is not a valid username.'
        pass_error = '' if self.valid_password(password) else 'That is not a valid password.'
        email_error = '' if self.valid_email(email) else 'That is not a valid email address.'
        verify_error = '' if self.match_password(password,verify) else 'Those passwords do not match.'
        populate = { 'username': username, 'email': self.request.get("email"), 'name_error': name_error, 'pass_error': pass_error, 'email_error': email_error, 'verify_error': verify_error, 'dupe_name_error': dupe_name_error }
        if self.validate_form(username,password,verify,email,recs):
            pw_hash= self.make_pw_hash(username,password)
            u = User(username = username, password = pw_hash, email = email)
            u.put()
            id_cookie = self.hash_id_cookie(u.key().id())
            self.response.headers.add_header('Set-Cookie','id=%s; Path=/' % id_cookie)
            self.redirect('/welcome')
        else:
            self.render_form(populate=populate)

class WelcomePage(Handler):
    def no_id(self):
        self.write("Welcome! Would you like to <a href='/signup'>register</a> or <a href='/login'>log in</a>?")
    def get(self):
        id = self.request.cookies.get('id',0)
        if id:
            id_no = int(id.split('|')[0])
            if id == self.hash_id_cookie(id_no):
                u = User.get_by_id(id_no)
                name = u.username
                self.write("Welcome, %s!" % name)
            else:
                self.no_id()
        else:
            self.no_id()
    
class UserPage(Handler):
    def get(self):
        users = db.GqlQuery("SELECT * FROM User ORDER BY username")
        for u in users:
            self.write("%s" %u.username)
            self.write(" %s" %u.created)
            self.write("<br>")
            
class LoginPage(Handler):
    def render_form(self,populate = {'error': ''}):
        self.render("login.html",populate=populate)
    def get(self):
        self.render_form("login.html")
    def post(self):
        name = self.request.get("username")
        pw = self.request.get("password")
        name_recs = db.GqlQuery("SELECT * FROM User WHERE username='%s'" % name)
        recs = []
        for rec in name_recs:
            recs.append(recs)
        if len(recs) > 0:
            user_id = name_recs[0].key().id()
            u = User.get_by_id(user_id)
            pw_hash = u.password
            salt = pw_hash.split('|')[1]
            if self.make_pw_hash(name,pw,salt) == pw_hash:
                self.write("Yay")
                id_cookie = self.hash_id_cookie(user_id)
                self.response.headers.add_header('Set-Cookie','id=%s; Path=/' % id_cookie)
                self.redirect('/welcome')
        self.render_form(populate = {'error': 'Invalid user name or password.'})
            
class LogoutPage(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie','id=''; Path=/')
        self.redirect('/signup')
        
                    
class NewTaskPage(Handler):
    def valid_task_name(self,tname):
        if tname and len(tname) <= 500:
            return True
        return False
    def get(self):
        id_cookie = self.request.cookies.get("id",0)
        id_no = self.valid_id_cookie(id_cookie)
        if id_no:
            self.render('taskedit.html')
        else:
            self.write("Please log in")
    def post(self):
        id_cookie = self.request.cookies.get("id",0)
        id_no = self.valid_id_cookie(id_cookie)
        if id_no:
            tname = self.request.get('tname')
            tdesc = self.request.get('tdesc')
            deadline = self.request.get('deadline')
            d,m,yr = deadline.split('/')
            deadline_obj = datetime.date(int(yr),int(m),int(d))
            importance = self.request.get('importance')
            if self.valid_task_name(tname):
                t = Task(userid = int(id_no), tdesc = tdesc, tname = tname,  deadline = deadline_obj, importance = int(importance), parentid = 0)
                t.put()
                self.redirect('/taskmanager')
        else:
            self.redirect('/')

class TaskManagerPage(Handler):
    def get(self):
        user = self.valid_user()
        if user:
            tasks = db.GqlQuery("SELECT * FROM Task WHERE userid = %s" % user.key().id())
            self.write("<h1>Walrus Task Manager</h1>")
            self.write("<p>%s, these are your active tasks:</p>" % user.username)
            for t in tasks:
                self.write("%s <br>" % t.tname)
            self.write("<a href='/newtask'>Add a new task</a>")
            self.render("tasklist.html")
        else:
            self.redirect('/')
            
class ProfilePage(Handler):
    def get(self):
        user = self.valid_user()
        if user:
            self.write("<h1>Profile Page</h1>")
            self.write(user.username)
            self.write(user.email)
            self.render("profileform.html")
        else:
            self.redirect('/')
                    
app = webapp2.WSGIApplication([('/', MainPage), ('/signup', RegisterPage), ('/welcome', WelcomePage), ('/users',UserPage), ('/login', LoginPage), ('/logout',LogoutPage), ('/newtask',NewTaskPage), ('/taskmanager', TaskManagerPage), ('/profile', ProfilePage)],
                              debug=True)
