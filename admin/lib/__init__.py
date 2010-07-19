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

import os
from google.appengine.ext import webapp
from google.appengine.ext.webapp import template
from google.appengine.api import users

def RequiresLogin(fun):
  def RequiresLoginDecorator(self, *args, **kwargs):
    if not self.user:
      self.redirect(users.create_login_url("/"))
      return
    return fun(self, *args, **kwargs)
  return RequiresLoginDecorator


class BaseHandler(webapp.RequestHandler):
  def initialize(self, request, response):
    super(BaseHandler, self).initialize(request, response)
    self.user = users.get_current_user()

  def GetTemplatePath(self, template):
    return os.path.join(os.path.dirname(__file__), "..", "templates", template)

  def RenderTemplate(self, template_name, template_values):
    self.response.out.write(
        template.render(self.GetTemplatePath(template_name),
                               template_values))

  def GetTemplateValues(self):
    return {
        "user": self.user,
        "login_url": users.create_login_url("/"),
        "logout_url": users.create_logout_url("/"),
    }
