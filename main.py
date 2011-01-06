# This code is in Public Domain. Take all the code you want, we'll just write more.

import StringIO, os, re, string, sha, time, random, cgi, urllib, datetime, pickle, logging
import wsgiref.handlers

from google.appengine.api import users
from google.appengine.api import memcache
from google.appengine.ext import webapp
from google.appengine.ext import db
from google.appengine.ext.webapp import template

from django.utils import feedgenerator
from django.template import Context, Template

from model import FofouSettings, FofouUser, Forum, Topic, Post

DEBUG = True

HTTP_NOT_ACCEPTABLE = 406
HTTP_NOT_FOUND = 404
HTTP_DATE_FMT = "%a, %d %b %Y %H:%M:%S GMT"

# Cookie code based on http://code.google.com/p/appengine-utitlies/source/browse/trunk/utilities/session.py
FOFOU_COOKIE = "fofou-uid"

# Valid for 120 days
COOKIE_EXPIRE_TIME = 120

SKINS = ["default"]

BANNED_IPS = { }

RE_VALID_URL = re.compile(r'^[a-z0-9]+([_\-]?[a-z0-9]+)*$')

def to_unicode(val):
  if isinstance(val, unicode): 
    return val
  try: return unicode(val, 'latin-1')
  except: pass
  try: return unicode(val, 'ascii')
  except: pass
  try: return unicode(val, 'utf-8')
  except: raise

def to_utf8(s):
  return to_unicode(s).encode("utf-8")

class FofouBase(webapp.RequestHandler):
  """ A base class for all request handlers. Abstracts cookies and response writes. """
  
  def __init__(self, *args, **kwargs):
    super(FofouBase, self).__init__(*args, **kwargs)
    self.settings = FofouSettings.load()
  
  def template_out(self, template_path, template_values):
    # just a dummy call to to the function
    self.get_cooke()
    self.response.headers['Content-Type'] = 'text/html'
    self.response.out.write( template.render(template_path, template_values) )

  _cookie = None
  def get_cooke(self):
    if self._cookie:
      return self._cookie

    try:
      fid = self.request.cookies[FOFOU_COOKIE]
    except KeyError:
      fid = sha.new(repr(time.time())).hexdigest()
      expires = datetime.datetime.now() + datetime.timedelta(COOKIE_EXPIRE_TIME)
      self.response.headers['Set-Cookie'] = '%s=%s; expires=%s; path=/' % (FOFOU_COOKIE, fid, expires.strftime(HTTP_DATE_FMT))

    self._cookie = fid
    return self._cookie
  
  cookie = property(get_cooke)

class ManageSettings(FofouBase):
  
  def get(self):
    user = users.get_current_user()
    is_admin = users.is_current_user_admin()
    
    if not is_admin:
      return self.redirect("/")
    
    tvals = {
      'isadmin': is_admin,
      'user': user,
      'settings': self.settings,
      'logout_url': users.create_logout_url("/")
    }
    return self.template_out("skins/default/settings.html", tvals)
  
  def post(self):
    user = users.get_current_user()
    is_admin = users.is_current_user_admin()
    
    if not is_admin:
      return self.redirect("/")
    
    banned = self.request.get('banned_ips', '').strip()
    email_white = self.request.get('email_whitelist', '').strip()
    email_black = self.request.get('email_blacklist', '').strip()

    if os.environ['REMOTE_ADDR'] in banned:
      banned = banned.replace(os.environ['REMOTE_ADDR'], "")
      
    self.settings.email_blacklist = email_black
    self.settings.email_whitelist = email_white
    self.settings.banned_ips = banned
    
    self.settings.put()
    
    return self.redirect(self.request.url)

class ManageForums(FofouBase):

  def init(self):
    """ Initializes the ManageForums views """
    
    self.tpl    = "skins/default/forum_list.html"
    self.forums = db.GqlQuery("SELECT * FROM Forum")    
    self.admin  = users.is_current_user_admin()
    self.user   = users.get_current_user()
    self.forum  = None
    self.redir  = False
    self.tvals  = {
      'logout_url': users.create_logout_url("/"),
      'hosturl': self.request.host_url,
      'isadmin': self.admin,
      'msg': self.request.get('msg'),
      'forums': self.forums,
      'user': self.user
    }
    forum_key = self.request.get('forum_key')
    if forum_key:
      self.forum = db.get( db.Key( forum_key ) )
      if not self.forum:
        self.redir = True

  def get(self):
    """ Responds to GET requests to the /manageforums URL """
    self.init()

    if self.redir or not self.admin:
      return self.redirect("/")
    
    # We are disabling/enabling or editing a forum
    forum = self.forum
    if forum:
      forum.tagline = forum.tagline or "Tagline"
      forum.title_non_empty = forum.title or "Title"
      forum.sidebar_non_empty = forum.sidebar or "Sidebar"

      if self.request.get('disable') or self.request.get('enable'):
        if self.request.get('disable'):
          forum.is_disabled = True
          msg = "Forum %s has been disabled" % (forum.title or forum.url)
        elif self.request.get('enable'):
          forum.is_disabled = False
          msg = "Forum %s has been enbled" % (forum.title or forum.url)
        forum.put()
        return self.redirect("/manageforums?msg=%s" % urllib.quote( to_utf8( msg ) ) )
    
    self.tvals['forum'] = forum
    return self.template_out(self.tpl, self.tvals)

  def post(self):
    """ Responds to POST requests to the /manageforums URL """
    self.init()
    
    if self.redir or not self.admin:
      return self.redirect("/")
    
    if not RE_VALID_URL.match( self.request.get('url') ) or \
       not self.forum and Forum.gql("WHERE url = :1", self.request.get('url') ).get():
      self.tvals.update({
        'errmsg': "Url contains illegal characters or is already used by another forum",
        'hosturl': self.request.host_url,
        'forum': { 
          'url': self.request.get('url'), 
          'title': self.request.get('title'), 
          'tagline': self.request.get('tagline'), 
          'sidebar': self.request.get('sidebar'), 
          'analytics_code': self.request.get('analytics_code')
        }
      })
      return self.template_out(self.tpl, self.tvals)
    
    if self.forum:
      forum         = self.forum
      forum.url     = self.request.get('url')
      forum.title   = self.request.get('title')
      forum.tagline = self.request.get('tagline')
      forum.sidebar = self.request.get('sidebar')
      forum.analytics_code = self.request.get('analytics_code')
    else:
      forum = Forum(
        url=self.request.get('url'), 
        title=self.request.get('title'), 
        tagline=self.request.get('tagline'), 
        sidebar=self.request.get('sidebar'), 
        analytics_code=self.request.get('analytics_code')
      )
    
    forum.put()
    return self.redirect("/manageforums?msg=%s" % urllib.quote( to_utf8( "Forum has been successfully edited/added" ) ) )

# Responds to GET /postdel?<post_id> and /postundel?<post_id>
class PostDelUndel(webapp.RequestHandler):

  def get(self):
    forum = Forum.from_url(self.request.path_info)
    is_admin = users.is_current_user_admin()

    # Only admins can delete or undelete posts
    if not forum or not is_admin:
      return self.redirect("/")

    post  = db.get( db.Key.from_path( 'Post', int(self.request.query_string) ) )
    topic = post.topic
    first = Post.gql("WHERE topic=:1 ORDER BY created_on", topic).get()

    if not post or topic.forum.key() != forum.key():
      return self.redirect(forum.root())

    if self.request.path.endswith("/postdel") and not post.is_deleted:
      post.is_deleted = True
      post.put()
      if first.key() == post.key():
        topic.is_deleted = True
        forum.num_topics -= 1
        forum.num_posts -= topic.ncomments
      else:
        topic.ncomments -= 1
        forum.num_posts -= 1
      topic.put()
      forum.put()
        
    elif post.is_deleted:
      post.is_deleted = False
      post.put()
      if first.key() == post.key():
        topic.is_deleted = False
        forum.num_topics += 1
        forum.num_posts += topic.ncomments
      else:
        topic.ncomments += 1
        if not topic.is_deleted:
          forum.num_posts += 1
      forum.put()      
      topic.put()

    return self.redirect( "%stopic?id=%s" % (forum.root(), topic.id) )

# Responds to GET /postdel?<post_id> and /postundel?<post_id>
class LockTopic(webapp.RequestHandler):

  def get(self):
    forum = Forum.from_url(self.request.path_info)
    is_admin = users.is_current_user_admin()

    # Only admins can delete or undelete posts
    if not forum or not is_admin:
      return self.redirect("/")

    try:
      topic = db.get( db.Key.from_path( 'Topic', int(self.request.get('id')) ) )
    except ValueError:
      return self.redirect( forum.root() )
    

    if topic:
      topic.is_locked = not topic.is_locked
      topic.put()

    return self.redirect( forum.root() )

# Responds to /, shows list of available forums or redirects to forum management page if user is admin
class ForumList(FofouBase):
  def get(self):
    user = users.get_current_user()
    is_admin = users.is_current_user_admin()
    
    if is_admin:
      return self.redirect("/manageforums")
    
    if not self.settings.check_ip(os.environ['REMOTE_ADDR']):
      return self.response.out.write('Your IP address has been banned')
    
    if not self.settings.check_user( user ):
      return self.redirect( users.create_login_url("/") )
    
    tvals = {
      'forums': db.GqlQuery("SELECT * FROM Forum"),
      'isadmin': is_admin,
      'login_url': users.create_login_url("/"),
      'logout_url': users.create_logout_url("/"),
      'user': user
    }

    self.template_out("skins/default/forum_list.html", tvals)

class TopicList(FofouBase):
  """ Shows a list of topics, potentially starting from topic with an offset """

  def get(self):
    forum = Forum.from_url(self.request.path_info)
    user = users.get_current_user()
    is_admin = users.is_current_user_admin()
    
    if not forum or (forum.is_disabled and not is_admin):
      return self.redirect("/")
    
    if not is_admin and not self.settings.check_ip(os.environ['REMOTE_ADDR']):
      return self.response.out.write('Your IP address has been banned')

    if not is_admin and not self.settings.check_user( user ):
      return self.redirect( users.create_login_url("/") )

    offset, topics = Topic.getlist(forum, is_admin=is_admin, offset=self.request.get("from") or None)
    for topic in topics:
      topic.excerpt = Post.gql("WHERE topic = :1 ORDER BY created_on", topic)[0].get_excerpt()

    tvals = {
      'user': user,
      'analytics_code': forum.analytics_code or "",
      'siteurl': self.request.url,
      'isadmin': is_admin,
      'forum' : forum,
      'topics': topics,
      'offset': offset,
      'login_url': users.create_login_url(forum.root()),
      'logout_url': users.create_logout_url(forum.root())
    }

    self.template_out("skins/default/topic_list.html", tvals)

# responds to /<forumurl>/topic?id=<id>
class TopicForm(FofouBase):

  def get(self):
    forum = Forum.from_url(self.request.path_info)
    is_admin = users.is_current_user_admin()
    user = users.get_current_user()
    
    if not forum or (forum.is_disabled and not is_admin):
      return self.redirect("/")
    
    if not is_admin and not self.settings.check_ip(os.environ['REMOTE_ADDR']):
      return self.response.out.write('Your IP address has been banned')

    if not is_admin and not self.settings.check_user( user ):
      return self.redirect( users.create_login_url("/") )
    
    try: 
      topic_id = int( self.request.get('id') or 0 )
    except ValueError:
      topic_id = 0

    if not topic_id:
      return self.redirect(forum.root())

    topic = db.get( db.Key.from_path('Topic', topic_id) )
    
    if not topic or (topic.is_deleted and not is_admin):
      return self.redirect(forum.root())
    
    # TODO: Make Pagination
    if is_admin:
      posts = Post.gql("WHERE topic = :1 ORDER BY created_on", topic)
    else:
      posts = Post.gql("WHERE topic = :1 AND is_deleted = False ORDER BY created_on", topic)
    
    tvals = {
      'user': user,
      'analytics_code' : forum.analytics_code or "",
      'isadmin': is_admin,
      'forum': forum,
      'topic': topic,
      'posts': posts,
      'login_url' : users.create_login_url(self.request.url),
      'logout_url' : users.create_logout_url(self.request.url)
    }
    self.template_out("skins/default/topic.html", tvals)

# Responds to /<forumurl>/post[?id=<topic_id>]
class PostForm(FofouBase):
  def get(self):
    is_admin = users.is_current_user_admin()
    forum = Forum.from_url(self.request.path_info)
    user = users.get_current_user()
    
    if not forum or (forum.is_disabled and not is_admin):
      return self.redirect("/")
    
    if not is_admin and not self.settings.check_ip(os.environ['REMOTE_ADDR']):
      return self.response.out.write('Your IP address has been banned')

    if not is_admin and not self.settings.check_user( user ):
      return self.redirect( users.create_login_url("/") )
    
    # Get user either by google user id or cookie
    if user:
      fuser = FofouUser.gql("WHERE user = :1", user).get()
    else: 
      fuser = FofouUser.gql("WHERE cookie = :1", self.cookie ).get()

    tvals = {
      'user': user,
      'isadmin': is_admin,
      'forum': forum,
      'fuser': fuser or {
        'email': user.email() if user else "",
        'name': user.nickname() if user else "",
        'remember_me': True
      },
      'post': { 'subject': '' },
      'login_url' : users.create_login_url(self.request.url),
      'logout_url' : users.create_logout_url(self.request.url)
    }
    
    topic_id = self.request.get('id')
    if topic_id:
      tvals['topic'] = db.get(db.Key.from_path('Topic', int(topic_id)))
      if not tvals['topic']:
        return self.redirect( forum.root() )

    self.template_out("skins/default/post.html", tvals)

  def post(self):
    forum = Forum.from_url(self.request.path_info)
    is_admin = users.is_current_user_admin()
    user = users.get_current_user()
    
    if not forum or (forum.is_disabled and not is_admin):
      return self.redirect("/")

    if not is_admin and not self.settings.check_ip(os.environ['REMOTE_ADDR']):
      return self.response.out.write('Your IP address has been banned')

    if not is_admin and not self.settings.check_user( user ):
      return self.redirect( users.create_login_url("/") )

    name = self.request.get('name').strip()
    email = self.request.get('email').strip()
    subject = self.request.get('subject').strip()
    message = to_unicode( self.request.get('message') ).strip()
    homepage = self.request.get('homepage').strip()
    homepage = "" if homepage == "http://" else homepage
    remember = bool(self.request.get('remember'))
    
    try: 
      topic_id = int( self.request.get('topic_id') or 0 )
      if topic_id:
        topic = db.get(db.Key.from_path('Topic', topic_id))
      else:
        topic = None
    except ValueError:
      topic = None
    
    if topic and topic.is_locked:
      return self.redirect( "%stopic?id=%s" % (forum.root(), topic.id) )
    
    # Perform simple validation
    errors = { 'valid': True }
    
    # First post must have a subject
    if not topic and not subject: 
      errors['valid'] = False
      errors['subject'] = "Subject required for new topic"
    
    if not message:
      errors['valid'] = False
      errors['message'] = "Message is required"
    
    # sha.new() doesn't accept Unicode strings, so convert to utf8 first
    sha1_digest = sha.new( message.encode('UTF-8') ).hexdigest()
    if Post.gql("WHERE sha1_digest = :1 AND topic = :2", sha1_digest, topic).get():
      errors['valid'] = False
      errors['message'] = "This is a duplicate post"

    if not errors['valid']:
      return self.template_out("skins/default/post.html", {
        'isadmin': is_admin,
        'user': user,
        'errors': errors,
        'forum': forum,
        'topic': topic and { 'id': topic_id, 'subject': topic.subject },
        'post': { 'message': message, 'subject': subject },
        'fuser': { 'name': name, 'email': email, 'homepage': homepage, 'remember_me': remember }
      })

    # Get user either by google user id or cookie. Create user objects if don't already exist    

    if user:
      fuser = FofouUser.gql("WHERE user = :1", user).get()
    else: 
      fuser = FofouUser.gql("WHERE cookie = :1", self.cookie).get()

    if not fuser:
      fuser = FofouUser(
        user = user or users.User('anonymous@example.com'),
        remember_me = remember, 
        email = email or 'anonymous@example.com', 
        name = name or 'Anonymous', 
        homepage = homepage,
        cookie = self.cookie )
    else:
      fuser.remember_me = remember
      fuser.email = email or 'anonymous@example.com'
      fuser.name = name or 'Anonymous'
      fuser.homepage = homepage

    if not topic:
      topic = Topic(forum=forum, subject=subject, created_by=fuser.name)
      forum.num_topics += 1
    else:
      topic.ncomments += 1
      forum.num_posts += 1
    
    topic.put()
    fuser.put()
    
    post = Post(
      topic = topic, 
      user = fuser, 
      user_ip = os.environ['REMOTE_ADDR'], 
      message = message, 
      sha1_digest = sha1_digest, 
      user_name = fuser.name,
      user_email = fuser.email,
      user_homepage = homepage
    )
    
    post.put()
    forum.put()

    self.redirect( "%stopic?id=%s" % (forum.root(), topic.id) )

if __name__ == "__main__":
  wsgiref.handlers.CGIHandler().run(webapp.WSGIApplication(
   [('/', ForumList),
    ('/manageforums', ManageForums),
    ('/managesettings', ManageSettings),
    ('/[^/]+/postdel', PostDelUndel),
    ('/[^/]+/postundel', PostDelUndel),
    ('/[^/]+/lock', LockTopic),
    ('/[^/]+/post', PostForm),
    ('/[^/]+/topic', TopicForm),
    ('/[^/]+/?', TopicList)], debug=DEBUG))
