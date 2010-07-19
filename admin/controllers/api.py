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


import hashlib
import csv
import datetime
import time
import logging

import lib
import model

class ApiPage(lib.BaseHandler):
  def initialize(self, request, response):
    super(lib.BaseHandler, self).initialize(request, response)
    self.hostname = self.request.GET.get("hostname", None)
    self.server = None
    if self.hostname:
			r = model.SmtpServer.gql("WHERE hostname = :1", self.hostname)
			if r.count() > 0:
				self.server = r[0]

  def check_hash(self, data):
    if not self.server: return False
    request_hash = self.request.GET.get("request_hash", None)
    sha1 = hashlib.sha1(self.server.secret_key)
    sha1.update(":")
    sha1.update(data)
    return request_hash == sha1.hexdigest()
  
class GetMappingsPage(ApiPage):
  def get(self):
    if not self.server:
      logging.error("Server '%s' not found" % (self.hostname,))
      self.error(403)
      self.response.out.write("Invalid hostname")
      return
    last_updated = self.request.GET.get("last_updated", "")
    if last_updated:
      ts = datetime.datetime.fromtimestamp(float(last_updated))
    if not self.check_hash(last_updated):
      logging.error("Request hash does not match")
      self.error(403)
      self.response.out.write("Request hash does not match")
      return
    
    version = int(self.request.GET.get("version", 0))
    
    q = model.Mapping.all()
    if last_updated:
      q.filter("last_updated >=", ts)
    q.order("last_updated")
    mappings = q.fetch(100)
    
    self.response.headers["Content-Type"] = "text/csv"
    writer = csv.writer(self.response.out)
    if version >= 1:
      writer.writerows((x.user, x.host, x.url,
                        time.mktime(x.last_updated.timetuple()), x.deleted)
                       for x in mappings)
    else:
      writer.writerows((x.user, x.host, x.url,
                        time.mktime(x.last_updated.timetuple()))
                       for x in mappings)


class UploadLogsPage(ApiPage):
  def post(self):
    if not self.server:
      logging.error("Server '%s' not found" % (self.hostname,))
      self.error(403)
      self.response.out.write("Invalid hostname")
      return
    if not self.check_hash(self.request.body):
      logging.error("Request hash does not match")
      self.error(403)
      self.response.out.write("Request hash does not match")
      return
    
    version = self.request.GET.get("version", 0)
    reader = csv.reader(self.request.body_file)
    if version >= 1:
      for id, user, host, level, ts, sender, rcpt, length, msg in reader:
        if user == "": user = None        
        mapping = model.Mapping.get_by_address(user, host)
        if not mapping:
          logging.error("Unable to find mapping for '%s@%s'" % (user, host))
          continue
        
        level = int(level)
        model.LogEntry(key_name="_"+id,
                       mapping=mapping,
                       server=self.server,
                       ts=datetime.datetime.utcfromtimestamp(float(ts)),
                       sender=sender,
                       recipient=rcpt,
                       length=int(length),
                       message=msg,
                       is_warning=level>=logging.WARNING,
                       is_error=level>=logging.ERROR).put()
    else:
      for id, key, level, ts, sender, rcpt, length, msg in reader:
        if "@" in key:
          user, host = key.split("@", 1)
        else:
          user = None
          host = key
        mapping = model.Mapping.get_by_address(user, host)
        if not mapping:
          logging.error("Unable to find mapping for '%s@%s'" % (user, host))
          continue
        
        level = int(level)
        model.LogEntry(key_name="_"+id,
                       mapping=mapping,
                       server=self.server,
                       ts=datetime.datetime.utcfromtimestamp(float(ts)),
                       sender=sender,
                       recipient=rcpt,
                       length=int(length),
                       message=msg,
                       is_warning=level>=logging.WARNING,
                       is_error=level>=logging.ERROR).put()

class AddSmtpHost(ApiPage):
	def get(self):
    # s = model.SmtpServer(hostname="hostname.as.reported.by.your.server",mxname="Testing",secret_key="key")
    # s.put()
		self.response.out.write("Done")
		return
