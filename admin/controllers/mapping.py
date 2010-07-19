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

import re
import hashlib
import logging
import random
import os

from google.appengine.api import urlfetch

import lib
# from lib import config
import model

class AddMappingPage(lib.BaseHandler):
  @lib.RequiresLogin
  def get(self):
    template_values = self.GetTemplateValues()
    template_values['type'] = self.request.GET.get("type", "basic")
    self.RenderTemplate("addmapping.html", template_values)

  @lib.RequiresLogin
  def post(self):
    type = self.request.POST.get("type", "basic")
    if type == "basic":
      user = self.request.POST.get("user", None)
      host = "s2w.m.ac.nz"
    elif type == "domain":
      user = None
      host = self.request.POST.get("host", None)
    url = self.request.POST.get("url", None)
    
    template_values = self.GetTemplateValues()
    template_values['type'] = type
    template_values['user'] = user
    template_values['host'] = host
    template_values['url'] = url
    
    if (type not in ("basic", "domain") or (type == "basic" and not user)
        or not host or not url or not url.startswith("http://")
        or url.rfind("/", 8) == -1):
      template_values['error'] = "Please fill in ALL the fields."
      self.RenderTemplate("addmapping.html", template_values)
      return
    
    if type == "basic" and not re.search("^[a-zA-Z0-9._-]{3,}$", user):
      template_values['error'] = ("The user field must be at least 3 characters "
                                  "long, and may only contain letters, numbers, "
                                  "dot (.), hyphen (-) and underscore (_) "
                                  "characters.")
      self.RenderTemplate("addmapping.html", template_values)
      return
    
    oldmapping = model.Mapping.get_by_address(user, host)
    if oldmapping and not oldmapping.deleted:
      template_values['error'] = ("That address is already in use. Please try another.")
      self.RenderTemplate("addmapping.html", template_values)
      return

    urlbase = url[:url.rfind("/")+1]
    # verify_hash = hashlib.sha1("%s:%s" % (config.secret_key, urlbase)).hexdigest()
    # verify_url = "%s/smtp2web_%s.html" % (url[:url.rfind("/")], verify_hash[:16])
    # template_values['verify_url'] = verify_url
    
    # if not os.environ["SERVER_SOFTWARE"].startswith("Development/"):
    #   if not self.request.POST.get("confirm", False):
    #     self.RenderTemplate("confirmmapping.html", template_values)
    #     return
    #   
    #   response = urlfetch.fetch(verify_url, method=urlfetch.HEAD)
    #   if str(response.status_code)[0] != "2":
    #     template_values['error'] = ("Could not fetch the verification page. Please "
    #                                 "ensure it exists in the correct location and "
    #                                 "is accessible, and try again.")
    #     self.RenderTemplate("confirmmapping.html", template_values)
    #     return
    
    if oldmapping:
      oldmapping.owner = self.user
      oldmapping.user = user
      oldmapping.host = host
      oldmapping.url = url
      oldmapping.deleted = False
      oldmapping.put()
    else:
      mapping = model.Mapping.get_or_insert(
          model.Mapping.get_key_name(user, host),
          owner = self.user,
          user = user,
          host = host,
          url = url)
      if mapping.owner != self.user:
        template_values['error'] = "That mapping is already in use."
        self.RenderTemplate("addmapping.html", template_values)
        return

    mxen = model.SmtpServer.all().fetch(100)
    mxen.sort(key=lambda x:random.random)
    template_values['mxen'] = mxen[:3]
    self.RenderTemplate("mappingadded.html", template_values)


class DeleteMappingPage(lib.BaseHandler):
  @lib.RequiresLogin
  def get(self, key_name):
    mapping = model.Mapping.get_by_key_name(key_name)
    if not mapping:
      self.error(404)
      self.response.out.write("Mapping not found.")
      return
    elif mapping.owner != self.user:
      self.error(403)
      self.response.out.write("You cannot view someone else's mapping!")
      return

    template_values = self.GetTemplateValues()
    template_values['mapping'] = mapping
    self.RenderTemplate("deletemapping.html", template_values)
  
  @lib.RequiresLogin
  def post(self, key_name):
    if self.request.POST.get("confirm", False) == "Yes":
      mapping = model.Mapping.get_by_key_name(key_name)
      if not mapping:
        self.error(404)
        self.response.out.write("Mapping not found.")
        return
      elif mapping.owner != self.user:
        self.error(403)
        self.response.out.write("You cannot view someone else's mapping!")
        return
      
      mapping.deleted = True
      mapping.put()
    self.redirect("/")


class LogsPage(lib.BaseHandler):
  def get(self, key_name):
    mapping = model.Mapping.get_by_key_name(key_name)
    if not mapping:
      self.error(404)
      self.response.out.write("Mapping not found.")
      return
    elif mapping.owner != self.user:
      self.error(403)
      self.response.out.write("You cannot view someone else's mapping!")
      return
    
    level = int(self.request.GET.get("level", logging.ERROR))
    count = min(max(int(self.request.GET.get("count", 20)), 0), 100)
    start = min(max(int(self.request.GET.get("start", 0)), 0), 1000-count)

    q = model.LogEntry.all()
    q.filter("mapping =", mapping)
    if level >= logging.ERROR:
      q.filter("is_error =", True)
    elif level >= logging.WARNING:
      q.filter("is_warning =", True)
    q.order("-ts")
    entries = q.fetch(count, start)
    logging.info(entries)
    
    template_values = self.GetTemplateValues()
    template_values['mapping'] = mapping
    template_values['entries'] = entries
    template_values['count'] = count
    template_values['current_count'] = min(count, len(entries))
    template_values['start'] = start
    template_values['prevstart'] = max(start - count, 0)
    template_values['has_more'] = len(entries) == count
    template_values['level'] = int(level)
    template_values['logging'] = logging
    self.RenderTemplate("logs.html", template_values)
