import logging
from google.appengine.ext import db

class FofouSettings(db.Model):
  banned_ips = db.TextProperty()
  email_whitelist = db.TextProperty()
  email_blacklist = db.TextProperty()
  
  @staticmethod
  def load():
    settings = FofouSettings.all()
    try:
      settings = settings[0]
    except IndexError:
      settings = FofouSettings(banned_ips="", email_whitelist="", email_blacklist="")
      settings.put()
      
    return settings

  def check_ip(self, ip):
    return ip not in ( x.strip() for x in self.banned_ips.replace("\r", "").split("\n"))
  
  def check_user(self, user):
    email = user.email() if user else None
    
    if self.email_blacklist and email in ( x.strip() for x in self.email_blacklist.replace("\r", "").split("\n")):
      return False

    elif self.email_whitelist and email not in ( x.strip() for x in self.email_whitelist.replace("\r", "").split("\n")):
      return False

    return True
  
class FofouUser(db.Model):
  # According to docs UserProperty() cannot be optional, so for anon users we set it to value returned by anonUser() function
  # user is uniquely identified by either user property (if not equal toanonUser()) or cookie
  user = db.UserProperty()
  
  cookie = db.StringProperty()
  # email, as entered in the post form, can be empty string
  email = db.StringProperty()
  # name, as entered in the post form
  name = db.StringProperty()
  # homepage - as entered in the post form, can be empty string
  homepage = db.StringProperty()
  # value of 'remember_me' checkbox selected during most recent post
  remember_me = db.BooleanProperty(default=True)

class Forum(db.Model):
  # Urls for forums are in the form /<urlpart>/<rest>
  url = db.StringProperty(required=True)
  # What we show as html <title> and as main header on the page
  title = db.StringProperty()
  # a tagline is below title
  tagline = db.StringProperty()
  # stuff to display in left sidebar
  sidebar = db.TextProperty()
  # if true, forum has been disabled. We don't support deletion so that forum can always be re-enabled in the future
  is_disabled = db.BooleanProperty(default=False)
  # just in case, when the forum was created. Not used.
  created_on = db.DateTimeProperty(auto_now_add=True)
  # name of the skin (must be one of SKINS)
  skin = db.StringProperty()
  # Google analytics code
  analytics_code = db.StringProperty()
  
  num_posts = db.IntegerProperty(required=False, default=0)
  num_topics = db.IntegerProperty(required=False, default=0)
  
  # A class method for getting Forum instances based on forum urls
  @staticmethod
  def from_url(url):
    return Forum.gql("WHERE url = :1", (url[1:] if url.startswith("/") else url).split("/")[0]).get()

  def enable_txt(self):
    return "enable" if self.is_disabled else "disable"

  def enable_url(self):
    return "enable=yes" if self.is_disabled else "disable=yes"

  def root(self):
    return "/%s/" % self.url

# A forum is collection of topics
class Topic(db.Model):
  forum = db.Reference(Forum, required=True)
  subject = db.StringProperty(required=True)
  created_on = db.DateTimeProperty(auto_now_add=True)
  # name of person who created the topic. Duplicates Post.user_name
  # of the first post in this topic, for speed
  created_by = db.StringProperty()
  # just in case, not used
  updated_on = db.DateTimeProperty(auto_now=True)
  # True if first Post in this topic is deleted. Updated on deletion/undeletion
  # of the post
  is_deleted = db.BooleanProperty(default=False)
  
  is_locked = db.BooleanProperty(default=False)

  # ncomments is redundant but is faster than always quering count of Posts
  ncomments = db.IntegerProperty(default=0)
  
  @staticmethod
  def getlist(forum, is_admin=False, offset="", max_topics=75):
    q = Topic.all().filter("forum =", forum)
    
    if not is_admin:
      q.filter("is_deleted =", False)
      
    topics = q.order("-created_on").with_cursor(offset).fetch( max_topics )
    new_offset = 0 if len(topics) < max_topics else q.cursor()
    return new_offset, topics
  
  @property
  def id(self):
    return self.key().id()

def ip2long(ip):
  return reduce(lambda x, y: x + y, (int(segment) * (256**(3-power)) for power, segment in enumerate(ip.split('.'))))
  
class Post(db.Model):
  
  def __init__(self, *args, **kwargs):
    if 'user_ip' in kwargs and isinstance(kwargs['user_ip'], str):
      kwargs['user_ip'] = ip2long( kwargs['user_ip'] )

    super(Post, self).__init__(*args, **kwargs)

  topic = db.Reference(Topic, required=True)
  created_on = db.DateTimeProperty(auto_now_add=True)
  message = db.TextProperty(required=True)
  sha1_digest = db.StringProperty(required=True)
  
  # admin can delete/undelete posts. If first post in a topic is deleted, that means the topic is deleted as well
  is_deleted = db.BooleanProperty(default=False)
  
  # ip address from which this post has been made
  user_ip = db.IntegerProperty(required=True)
  user = db.Reference(FofouUser, required=True)
  
  # user_name, user_email and user_homepage might be different than name/homepage/email fields in user object, since they can be changed in FofouUser
  user_name = db.StringProperty()
  user_email = db.StringProperty()
  user_homepage = db.StringProperty()
    
  @property
  def ip():
    def fget(self):
      return ".".join(( str(int(self.user_ip >> (24 - (x * 8)) & 0xFF)) for x in range(0,4) ))

    def fset(self, ip):
      self.user_ip = ip2long(ip)

  @property
  def id(self):
    return self.key().id()

  def get_excerpt(self):
    """ Returns the first 50 words of a post. Appends ... if this post has more than 50 words """
    words = self.message.split(" ")
    return " ".join(words[:50]) + ("" if len(words) <= 50 else " ...")
