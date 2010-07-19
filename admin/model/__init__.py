# Copyright 2008 arachnid AT notdot.net,
#           2010 Patrick Quinn-Graham
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

from google.appengine.ext import db
import logging
import hashlib
import math

class UserInfo(db.Model):
  user = db.UserProperty(required=True)


class Mapping(db.Model):
  owner = db.UserProperty(required=True)
  user = db.StringProperty()
  host = db.StringProperty(required=True)
  url = db.LinkProperty(required=True)
  created = db.DateTimeProperty(required=True, auto_now_add=True)
  last_updated = db.DateTimeProperty(required=True, auto_now=True)
  deleted = db.BooleanProperty(required=True, default=False)

  @classmethod
  def get_key_name(cls, user,host):
    return "_"+hashlib.sha1("%s@%s"%(user, host)).hexdigest()

  @classmethod
  def get_by_address(cls, user, host):
    return cls.get_by_key_name(cls.get_key_name(user, host))
  
  def get_name(self):
    if self.user:
      return "%s@%s" % (self.user, self.host)
    else:
      return self.host


class SmtpServer(db.Model):
  hostname = db.StringProperty(required=True)
  # The name to display in the list of MXen.
  mxname = db.StringProperty(required=True)
  secret_key = db.TextProperty(required=True)


class LogEntry(db.Model):
  mapping = db.ReferenceProperty(Mapping, required=True)
  server = db.ReferenceProperty(SmtpServer, required=True)
  ts = db.DateTimeProperty(required=True, auto_now_add=True)
  sender = db.EmailProperty(required=True)
  recipient = db.EmailProperty(required=True)
  length = db.IntegerProperty(required=True)
  message = db.TextProperty()
  is_error = db.BooleanProperty(required=True, default=False)
  is_warning = db.BooleanProperty(required=True, default=False)

  def human_size(self):
    return "%d kb" % math.ceil(self.length / 1024.0)
