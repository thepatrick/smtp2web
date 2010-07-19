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

from zope.interface import implements

from twisted.application import service
from twisted.application import internet
from twisted.internet import protocol, defer, reactor
from twisted.mail import smtp
from twisted.python import log
from twisted.web import client
import twisted.internet.error

import cgi
import csv
import cPickle
import cStringIO
import datetime
import hashlib
import logging
import os
import re
import socket
import sys
import time
import urllib
import urlparse
import uuid

from email.parser import Parser
import quopri

def getPage(url, *args, **kwargs):
  scheme, host, port, path = client._parse(url)
  factory = client.HTTPClientFactory(url, *args, **kwargs)
  factory.noisy = False
  if scheme == "https":
    from twisted.internet import ssl
    reactor.connectSSL(host, port, factory, ssl.ClientContextFactory())
  else:
    reactor.connectTCP(host, port, factory)
  return factory.deferred


class Settings(object):
  def __init__(self, **kwargs):
    # Externally accessed attributes
    self.max_message_size = 1048576
    self.usermap = {}
    self.logentries = []
    
    # Internal attributes
    self.usermap_lastupdated = None
    self.sync_interval = 60.0
    self.master_host = "s2w.m.ac.nz"
    self.state_file = None
    self.hostname = socket.getfqdn()
    self.secret_key = None
    self.getPage = getPage
    self.mapping_fetch_limit = 100
    self.log_post_limit = 50

    for key, val in kwargs.iteritems():
      setattr(self, key, val)
  
  def findHandler(self, user, host):
    mapping = self.usermap.get(host, None)
    if not mapping: return None
    return mapping.findHandler(user)
  
  def load(self):
    if not os.path.exists(self.state_file): return
    try:
      f = open(self.state_file, "r")
      self.usermap, self.usermap_lastupdated = cPickle.load(f)
      f.close()
    except IOError, e:
      log.err("Unable to load state file; starting from scratch.")
  
  def save(self):
    f = open(self.state_file, "w+")
    cPickle.dump((self.usermap, self.usermap_lastupdated), f)
    f.close()

  def updateMappings(self):
    qs = {
        "hostname": self.hostname,
        "last_updated": self.usermap_lastupdated or "",
        "version": 1,
        "limit": self.mapping_fetch_limit,
    }
    qs["request_hash"] = hashlib.sha1(
        "%s:%s" % (self.secret_key, qs["last_updated"])).hexdigest()
    url = "http://%s/api/get_mappings?%s" % (self.master_host,
                                             urllib.urlencode(qs))
    ret = self.getPage(url, agent="s2w-smtpd/1.1 (s2w.m.ac.nz)", timeout=30)
    
    def _doUpdate(result):
      result = [x for x in result.split("\n") if x]
      if len(result) > 0:
        reader = csv.reader(result)
        updated = 0
        for i, (user, host, url, ts, deleted) in enumerate(reader):
          if i == 0 and ts == self.usermap_lastupdated: continue
          updated += 1  
          
          if host not in self.usermap:
            self.usermap[host] = DomainMapping()
          
          mapping = self.usermap[host]
          handler = MessageHandler(url)
          if deleted == "True":
            if not user:
              mapping.deleteMapping(".*", True)
            else:
              mapping.deleteMapping(user, False)
          else:
            if not user:
              mapping.updateMapping("", True, handler, sys.maxint)
            else:
              mapping.updateMapping(user, False, handler, 0)
          self.usermap_lastupdated = ts
        if updated:
          log.msg("Updated %d user map entries" % (updated, ))
        
        if len(result) == self.mapping_fetch_limit:
          return self.updateMappings()
        else:
          return result
    ret.addCallback(_doUpdate)
    
    def _handleError(failure):
      log.err("Error fetching handler updates from %s: %s"
              % (url, str(failure.value)))
    ret.addErrback(_handleError)
    return ret
  
  def uploadLogs(self):
    data = cStringIO.StringIO()
    writer = csv.writer(data)
    writer.writerows(self.logentries[:self.log_post_limit])
    data = data.getvalue()
    sha1 = hashlib.sha1(self.secret_key)
    sha1.update(":")
    sha1.update(data)
    request_hash = sha1.hexdigest()
    
    url = ("http://%s/api/upload_logs?version=1&hostname=%s&request_hash=%s"
           % (self.master_host, self.hostname, request_hash))
    ret = self.getPage(url, method="POST", postdata=data,
                       headers={"Content-Type": "text/csv"},
                       agent="s2w-smtpd/1.1 (s2w.m.ac.nz)", timeout=30)

    def _handleResponse(result):
      self.logentries[:self.log_post_limit] = []
      if self.logentries:
        return self.uploadLogs()
    ret.addCallback(_handleResponse)

    def _handleError(failure):
      log.err("Error uploading log entries to %s: %s"
              % (url, str(failure.value)))
    ret.addErrback(_handleError)
    
    return ret
  
  def sync(self):
    """Syncs with the database."""
    mapping_update = self.updateMappings()
    mapping_update.addCallback(lambda result: self.save())
    dl = defer.DeferredList([mapping_update, self.uploadLogs()])
    def _reSync(result):
      reactor.callLater(self.sync_interval, self.sync)
    dl.addBoth(_reSync)


class MessageSubmissionError(Exception):
  pass

class MessageHandler(object):
  def __init__(self, url):
    self.url = url
    self.id = None

  def invoke(self, sender, rcpt, message):
    a = Parser()
    em = a.parsestr(message)
    text_block = em
    html_block = None
    if(em.is_multipart()):		
    	for part in em.walk():
    		if(part.get_content_type() == "text/plain"):
    			text_block = part
    		if(part.get_content_type() == "text/html"):
    			html_block= part
    		if(part.get_content_maintype() == "image"):
    			print "This is an image! " + part.get_filename("none." + part.get_content_subtype())
    if(text_block):
    	text_payload = text_block.get_payload(None, True)
    if(html_block):
    	html_payload = html_block.get_payload(None, True)
    else:
    	html_payload = ""

    postbody = {}
    counters = {}
    
    for key, value in em.items():
    	is_multiple = em.get_all(key)
    	if(len(is_multiple) > 1):
    		if key in counters:
    			counters[key] = counters[key] + 1
    		else:
    			counters[key] = 0
    		key = key + "[" + str(counters[key]) + "]"
    	postbody[key] = value
    
    postbody['plain'] = text_payload
    postbody['html'] = html_payload
			
    urlparts = urlparse.urlparse(self.url)
    qs = cgi.parse_qsl(urlparts.query, True)
    qs.append(("from", sender))
    qs.append(("to", rcpt))
    url = urlparse.urlunparse(urlparts[:4]+(urllib.urlencode(qs), urlparts[5]))
    ret = getPage(url, method="POST", postdata=urllib.urlencode(postbody),
                  headers={"Content-Type": "application/x-www-form-urlencoded"},
                  agent="s2w-smtpd/1.1 (s2w.m.ac.nz)", timeout=30)
		
  	
    def handleError(failure):
      err = None
      if failure.type == twisted.web.error.Error:
        raise MessageSubmissionError(
            "Received %s %s from server when sending POST request to %s"
            % (failure.value.args[:2] + (url,)))
      elif failure.type == twisted.internet.error.ConnectionRefusedError:
        raise MessageSubmissionError("Connection refused by %s"
                                     % (urlparts.netloc, ))
      else:
        return failure

    ret.addErrback(handleError)
    return ret


class DomainMapping(object):
  def __init__(self):
    self._users = dict()
    self._regexes = list()
    self._regexmap = dict()
  
  def updateMapping(self, id, is_regex, handler, priority):
    assert handler.id == None
    handler.id = id
    if is_regex:
      if not id:
        entry = (re.compile(".*"), handler, priority)
      else:
        entry = (re.compile(id), handler, priority)
      if id in self._regexmap:
        i = self._regexes.index(self._regexmap[id])
        self._regexes[i] = entry
      else:
        self._regexes.append(entry)
      self._regexes.sort(key=lambda x:x[2])
      self._regexmap[id] = entry
    else:
      self._users[id] = handler
  
  def deleteMapping(self, id, is_regex):
    if is_regex:
      if id in self._regexmap:
        self._regexes.remove(self._regexmap[id])
        del self._regexmap[id]
    else:
      if id in self._users:
        del self._users[id]
  
  def findHandler(self, user):
    if user in self._users:
      return self._users[user]
    else:
      for regex, handler, priority in self._regexes:
        if regex.search(user):
          return handler
      return None


class Message(object):
  implements(smtp.IMessage)

  def __init__(self, settings, sender, rcpt, handler):
    self.settings = settings
    self.sender = sender
    self.rcpt = rcpt
    self.handler = handler
    self.lines = []
    self.total_length = 0
  
  def lineReceived(self, line):
    line_len = len(line)
    self.total_length += line_len + 1
    if (self.total_length + line_len) <= self.settings.max_message_size:
      self.lines.append(line)
    else:
      ts = time.mktime(datetime.datetime.now().utctimetuple())
      self.settings.logentries.append(
          (str(uuid.uuid1()), self.handler.id, self.rcpt.dest.domain, logging.ERROR, ts,
          str(self.sender), str(self.rcpt.dest), self.total_length - 1,
          "Message exceeded maximum size of %d bytes." % (self.settings.max_message_size, )))
      raise smtp.SMTPServerError(552, "Message too long")
  
  def eomReceived(self):
    ret = self.handler.invoke(str(self.sender), str(self.rcpt.dest),
                              "\n".join(self.lines))
        
    def addLogEntry(response):
      ts = time.mktime(datetime.datetime.now().utctimetuple())
      self.settings.logentries.append(
          (str(uuid.uuid1()), self.handler.id, self.rcpt.dest.domain, logging.DEBUG,
           ts, str(self.sender), str(self.rcpt.dest), self.total_length - 1,
           None))
    ret.addCallback(addLogEntry)

    def handleError(failure):
      if failure.type == MessageSubmissionError:
        ts = time.mktime(datetime.datetime.now().utctimetuple())
        self.settings.logentries.append(
            (uuid.uuid1(), self.handler.id, self.rcpt.dest.domain, logging.ERROR,
             ts, str(self.sender), str(self.rcpt.dest), self.total_length - 1,
             str(failure.value)))
      return failure
    ret.addErrback(handleError)

    return ret
  
  def connectionLost(self):
    pass


class MessageDelivery(object):
  """Encapsulates a single message transaction."""
  implements(smtp.IMessageDelivery)
  
  def __init__(self, settings):
    self.sender = None
    self.settings = settings
  
  def validateTo(self, user):
    handler = self.settings.findHandler(user.dest.local, user.dest.domain)
    if not handler:
      raise smtp.SMTPBadRcpt(user.dest)
    return lambda: Message(self.settings, self.sender, user, handler)
  
  def validateFrom(self, helo, origin):
    self.sender = origin
    return origin

  def receivedHeader(self, helo, origin, recipients):
    heloStr = ""
    if helo[0]:
      heloStr = " helo=%s" % (helo[0],)
    domain = self.settings.hostname
    from_ = "from %s ([%s]%s)" % (helo[0], helo[1], heloStr)
    by = "by %s with s2w-smtpd (1.1; s2w.m.ac.nz) " % (domain, )
    for_ = "for %s; %s" % (' '.join(map(str, recipients)),
                           smtp.rfc822date())
    return "Received: %s\n\t%s\n\t%s" % (from_, by, for_)

class MessageDeliveryFactory(object):
  """One MessageDeliveryFactory is created per SMTP connection."""
  implements(smtp.IMessageDeliveryFactory)
  
  def __init__(self, settings):
    self.settings = settings
  
  def getMessageDelivery(self):
    return MessageDelivery(self.settings)


class ESMTPFactory(protocol.ServerFactory):
  """Called to create a new MessageDeliveryFactory for each connection."""
  protocol = smtp.ESMTP
  
  def __init__(self, settings):
    self.settings = settings
    reactor.callWhenRunning(self.settings.load)
    reactor.callWhenRunning(self.settings.sync)
    
  def buildProtocol(self, addr):
    p = self.protocol()
    p.deliveryFactory = MessageDeliveryFactory(self.settings)
    p.factory = self
    return p
