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

from twisted.internet import defer
from twisted.mail import smtp
from twisted.python import failure
from twisted.trial import unittest
import twisted.web.error
import cgi
import logging
import urlparse

import smtp2web

class MessageHandlerMock(object):
  def __init__(self, fails=False):
    self.id = None
    self.fails = fails
    self.invocations = []
    
  def invoke(self, sender, rcpt, message):
    self.invocations.append((sender, rcpt, message))
    if self.fails:
      return defer.fail(failure.Failure(smtp2web.MessageSubmissionError()))
    else:
      return defer.succeed(None)


class SettingsMock(smtp2web.Settings):
  def __init__(self):
    super(SettingsMock, self).__init__()
    self.max_message_size = 256
  
  def load(self):
    mapping = smtp2web.DomainMapping()
    mapping.updateMapping("test", False, MessageHandlerMock(False), 0)
    mapping.updateMapping("fail", False, MessageHandlerMock(True), 0)
    self.usermap['smtp2web.com'] = mapping
    
    mapping = smtp2web.DomainMapping()
    mapping.updateMapping("fail", False, MessageHandlerMock(True), 0)
    mapping.updateMapping("", True, MessageHandlerMock(False), 0)
    self.usermap['testdomain.com'] = mapping
  
  def sync(self):
    return


class ServerTest(unittest.TestCase):
  def setUp(self):
    self.settings = SettingsMock()
    self.settings.load()
    self.factory = smtp2web.ESMTPFactory(self.settings)
    self.smtp = self.factory.buildProtocol(None)
    # Cheating here to bypass testing smtp.ESMTP
    self.delivery = self.smtp.deliveryFactory.getMessageDelivery()
    self.sender = smtp.Address("test@test.com")
    self.test_message = """From: Me <me@us.com>
To: You <you@them.com>
Subject: Test

This is a test message."""
    
  def _sendMessageData(self, message_builder):
    message = message_builder()
    for line in self.test_message.split("\n"):
      message.lineReceived(line)
    return message.eomReceived()
  
  def _sendMessage(self, rcpt, send_body=True):
    self.failUnlessEqual(self.delivery.validateFrom(None, self.sender),
                         self.sender)
    ret = defer.maybeDeferred(self.delivery.validateTo, rcpt)
    if send_body:
      ret.addCallback(self._sendMessageData)
    return ret
  
  def _checkLogs(self, result, logs):
    for logentry, testentry in zip(self.settings.logentries, logs):
      (log_uuid, log_id, log_host, log_level, log_ts, log_sender, log_rcpt,
       log_len, log_msg) = logentry
      self.failUnlessEqual((log_id, log_host, log_level, log_sender, log_rcpt,
                            log_len), testentry)
  
  def test_send_message(self):
    """Checks overall message sending."""
    rcpt = smtp.User("test@smtp2web.com", None, object(), self.sender)
    ret = self._sendMessage(rcpt)
    handler = self.settings.usermap['smtp2web.com'].findHandler("test")
    ret.addCallback(lambda x: self.failUnlessEqual(handler.invocations,
                    [(str(self.sender), str(rcpt.dest), self.test_message)]))
    ret.addCallback(self._checkLogs, [("test", "smtp2web.com", logging.DEBUG,
                    str(self.sender), str(rcpt.dest), len(self.test_message))])
    return ret
  
  def test_send_wildcard(self):
    """Tests sending a message to a wildcard mapping."""
    rcpt = smtp.User("test@testdomain.com", None, object(), self.sender)
    ret = self._sendMessage(rcpt)
    handler = self.settings.usermap['testdomain.com'].findHandler("test")
    ret.addCallback(lambda x: self.failUnlessEqual(handler.invocations,
                    [(str(self.sender), str(rcpt.dest), self.test_message)]))
    ret.addCallback(self._checkLogs, [("", "testdomain.com", logging.DEBUG,
                    str(self.sender), str(rcpt.dest), len(self.test_message))])
    return ret

  def test_send_fail(self):
    """Tests sending with a handler that raises an exception."""
    rcpt = smtp.User("fail@smtp2web.com", None, object(), self.sender)
    ret = self._sendMessage(rcpt)
    ret.addCallbacks(
        self.fail,
        lambda failure: failure.trap(smtp2web.MessageSubmissionError)
    )
    handler = self.settings.usermap['smtp2web.com'].findHandler("fail")
    ret.addCallback(lambda x: self.failUnlessEqual(handler.invocations,
                    [(str(self.sender), str(rcpt.dest), self.test_message)]))
    ret.addCallback(self._checkLogs, [("fail", "smtp2web.com", logging.ERROR,
                    str(self.sender), str(rcpt.dest), len(self.test_message))])
    return ret

  def test_invalid_address(self):
    """Tests sending to an invalid address."""
    rcpt = smtp.User("doesnotexist@smtp2web.com", None, object(), self.sender)
    ret = self._sendMessage(rcpt, False)
    ret.addCallbacks(
        self.fail,
        lambda failure: failure.trap(smtp.SMTPBadRcpt)
    )
    ret.addCallback(self._checkLogs, [("doesnotexist", "smtp2web.com",
                    logging.ERROR, str(self.sender), str(rcpt.dest), 0)])
    return ret

  def test_invalid_domain(self):
    """Tests sending to a domain we don't have mappings for."""
    rcpt = smtp.User("user@invaliddomain.com", None, object(), self.sender)
    ret = self._sendMessage(rcpt, False)
    ret.addCallbacks(
        self.fail,
        lambda failure: failure.trap(smtp.SMTPBadRcpt)
    )
    ret.addCallback(self._checkLogs, [("user", "invaliddomain.com",
                    logging.ERROR, str(self.sender), str(rcpt.dest), 0)])
    return ret

  def test_message_too_long(self):
    """Tests sending a message that's too long."""
    rcpt = smtp.User("test@smtp2web.com", None, object(), self.sender)
    self.test_message += "-" * 256
    ret = self._sendMessage(rcpt)
    
    def _checkFailure(failure):
      failure.trap(smtp.SMTPServerError)
      self.failUnlessEqual(failure.value.code, 552)

    ret.addCallbacks(self.fail, _checkFailure)
    ret.addCallback(self._checkLogs, [("test", "smtp2web.com", logging.ERROR,
                    str(self.sender), str(rcpt.dest), len(self.test_message))])
    return ret


class FetcherMock(object):
  def __init__(self, failer, invocations):
    self.failer = failer
    self.invocations = invocations
    self.invoc_iter = iter(invocations)
  
  def __call__(self, url, **kwargs):
    try:
      expect_url, expect_kwargs, result, is_fail = self.invoc_iter.next()
      self.failer.failUnlessURLsEqual(url, expect_url)
      self.failer.failUnlessEqual(kwargs, expect_kwargs)
      if is_fail:
        return defer.fail(result)
      else:
        return defer.succeed(result)
    except StopIteration:
      self.failer.fail("Fetcher called more times than expected")
  
  def done(self):
    self.failer.failUnlessRaises(StopIteration, self.invoc_iter.next)


class SettingsTest(unittest.TestCase):
  def failUnlessURLsEqual(self, a, b):
    a = urlparse.urlparse(a)
    a = a[:4] + (sorted(cgi.parse_qsl(a.query)),) + a[5:]
    b = urlparse.urlparse(b)
    b = b[:4] + (sorted(cgi.parse_qsl(b.query)),) + b[5:]    
    self.failUnlessEqual(a, b)
  
  def setUp(self):
    self.settings = smtp2web.Settings(secret_key="asecret", master_host="test",
                                      hostname="testhost")
    self.mapping_urls = [
        "http://test/api/get_mappings?version=1&hostname=testhost&limit=100&"
        "last_updated=&request_hash=0c26b1a6cbd9541ff4cbee467680a83c2b163809",
        "http://test/api/get_mappings?version=1&hostname=testhost&limit=100&"
        "last_updated=1&request_hash=3884591e6b912ed6e375b3c04e5c51f7823a92cb",
        "http://test/api/get_mappings?version=1&hostname=testhost&limit=100&"
        "last_updated=2&request_hash=5fea55af7035c4225cbde97bcfe9a2439fde7bd8",
    ]

  def test_update_mappings(self):
    """A basic test of updateMappings."""
    self.settings.getPage = FetcherMock(self, [
      (self.mapping_urls[0], {"agent": "smtp2web/1.0", "timeout": 30},
       "test,smtp2web.com,http://www.smtp2web.com/test_email,1,False", False),
       
      (self.mapping_urls[1], {"agent": "smtp2web/1.0", "timeout": 30},
       ",testdomain.com,http://www.testdomain.com/blahblah,2,False", False),
    ])
    ret = self.settings.updateMappings()
    def _doChecks(result):
      self.failUnlessEqual(self.settings.findHandler("test", "smtp2web.com").url,
                           "http://www.smtp2web.com/test_email")
      self.assertEqual(self.settings.usermap_lastupdated, '1')
      return self.settings.updateMappings()
    ret.addCallback(_doChecks)
    def _doChecks2(result):
      self.failUnlessEqual(self.settings.findHandler("blah", "testdomain.com").url,
                           "http://www.testdomain.com/blahblah")
      self.assertEqual(self.settings.usermap_lastupdated, '2')
      self.settings.getPage.done()
    ret.addCallback(_doChecks2)
    return ret

  def test_updated_mapping(self):
    """Check that changes to an existing mapping are picked up."""
    self.settings.getPage = FetcherMock(self, [
      (self.mapping_urls[0], {"agent": "smtp2web/1.0", "timeout": 30},
       "test,smtp2web.com,http://www.smtp2web.com/test_email,1,False", False),

      (self.mapping_urls[1], {"agent": "smtp2web/1.0", "timeout": 30},
       "test,smtp2web.com,http://www.smtp2web.com/test_email2,2,False", False),
    ])
    ret = self.settings.updateMappings()
    def _doChecks(result):
      self.failUnlessEqual(self.settings.findHandler("test", "smtp2web.com").url,
                           "http://www.smtp2web.com/test_email")
      self.assertEqual(self.settings.usermap_lastupdated, '1')
      return self.settings.updateMappings()
    ret.addCallback(_doChecks)
    def _doChecks2(result):
      self.failUnlessEqual(self.settings.findHandler("test", "smtp2web.com").url,
                           "http://www.smtp2web.com/test_email2")
      self.assertEqual(self.settings.usermap_lastupdated, '2')
      self.settings.getPage.done()
    ret.addCallback(_doChecks2)
    return ret

  def test_deleted_mapping(self):
    """Check that deleted mappings are handled correctly."""
    self.settings.getPage = FetcherMock(self, [
      (self.mapping_urls[0], {"agent": "smtp2web/1.0", "timeout": 30},
       "test,smtp2web.com,http://www.smtp2web.com/test_email,1,False", False),

      (self.mapping_urls[1], {"agent": "smtp2web/1.0", "timeout": 30},
       "test,smtp2web.com,http://www.smtp2web.com/test_email2,2,True", False),

      (self.mapping_urls[2], {"agent": "smtp2web/1.0", "timeout": 30},
       "test,smtp2web.com,http://www.smtp2web.com/test_email2,2,True", False),
    ])
    ret = self.settings.updateMappings()
    def _doChecks(result):
      self.failUnlessEqual(self.settings.findHandler("test", "smtp2web.com").url,
                           "http://www.smtp2web.com/test_email")
      self.assertEqual(self.settings.usermap_lastupdated, '1')
      return self.settings.updateMappings()
    ret.addCallback(_doChecks)
    def _doChecks2(result):
      self.failUnlessEqual(self.settings.findHandler("test", "smtp2web.com"),
                           None)
      self.assertEqual(self.settings.usermap_lastupdated, '2')
    ret.addCallback(_doChecks2)
    ret.addCallback(lambda x: self.settings.updateMappings())
    ret.addCallback(_doChecks2)
    ret.addCallback(lambda x: self.settings.getPage.done())
    return ret

  def test_multiple_updates(self):
    """Checks that updates operate correctly when there are multiple pages of updates."""
    self.settings.mapping_fetch_limit = 2
    self.settings.getPage = FetcherMock(self, [
      ("http://test/api/get_mappings?version=1&hostname=testhost&limit=2&"
        "last_updated=&request_hash=0c26b1a6cbd9541ff4cbee467680a83c2b163809",
       {"agent": "smtp2web/1.0", "timeout": 30},
       "test,smtp2web.com,http://www.smtp2web.com/test_email,1,False\n"
       ",testdomain.com,http://www.testdomain.com/blahblah,2,False", False),

      ("http://test/api/get_mappings?version=1&hostname=testhost&limit=2&"
        "last_updated=2&request_hash=5fea55af7035c4225cbde97bcfe9a2439fde7bd8",
       {"agent": "smtp2web/1.0", "timeout": 30},
       ",testdomain.com,http://www.testdomain.com/blahblah,2,False", False),
    ])
    ret = self.settings.updateMappings()
    def _doChecks(result):
      self.failUnlessEqual(self.settings.findHandler("test", "smtp2web.com").url,
                           "http://www.smtp2web.com/test_email")
      self.failUnlessEqual(self.settings.findHandler("blah", "testdomain.com").url,
                           "http://www.testdomain.com/blahblah")
      self.assertEqual(self.settings.usermap_lastupdated, '2')
      self.settings.getPage.done()
    ret.addCallback(_doChecks)

  def test_update_error(self):
    """Tests errors fetching mapping updates are handled correctly."""
    self.settings.getPage = FetcherMock(self, [
      (self.mapping_urls[0], {"agent": "smtp2web/1.0", "timeout": 30},
       failure.Failure(twisted.web.error.Error("500 Internal Server Error")), True),
       
      (self.mapping_urls[0], {"agent": "smtp2web/1.0", "timeout": 30},
       "test,smtp2web.com,http://www.smtp2web.com/test_email,1,False", False),
    ])
    ret = self.settings.updateMappings()
    def _doChecks(result):
      self.failUnlessEqual(self.settings.findHandler("test", "smtp2web.com"),
                           None)
      self.assertEqual(self.settings.usermap_lastupdated, None)
      return self.settings.updateMappings()
    ret.addCallback(_doChecks)
    def _doChecks2(result):
      self.failUnlessEqual(self.settings.findHandler("test", "smtp2web.com").url,
                           "http://www.smtp2web.com/test_email")
      self.assertEqual(self.settings.usermap_lastupdated, '1')
      self.settings.getPage.done()
    ret.addCallback(_doChecks2)

  def test_log_upload(self):
    """Checks log uploads work correctly."""
    self.settings.logentries.append(
        ("test", "smtp2web.com", logging.DEBUG, "foo@bar.com",
         "test@smtp2web.com", 123))
    self.settings.getPage = FetcherMock(self, [
      ("http://test/api/upload_logs?version=1&hostname=testhost&"
       "request_hash=d0608d9c7b47543f0562c139a8d32a6ac85846ff",
       {"agent": "smtp2web/1.0", "timeout": 30, "method": "POST",
        "headers": {"Content-Type": "text/csv"},
        "postdata": "test,smtp2web.com,10,foo@bar.com,test@smtp2web.com,123\r\n"}, "", False)
    ])
    ret = self.settings.uploadLogs()
    ret.addCallback(lambda x: self.failUnlessEqual(self.settings.logentries, []))
    ret.addCallback(lambda x: self.settings.getPage.done())
    return ret

  def test_log_upload_multiple(self):
    """Checks log uploads work correctly."""
    self.settings.log_post_limit = 2
    self.settings.logentries = [
        ("test", "smtp2web.com", logging.DEBUG, "foo@bar.com",
         "test@smtp2web.com", 123),
        ("test", "smtp2web.com", logging.DEBUG, "bleh@whatever.com",
         "test@smtp2web.com", 456),
        ("", "testdomain.com", logging.DEBUG, "foo@bar.com",
         "blah@testdomain.com", 123),
    ]
    self.settings.getPage = FetcherMock(self, [
      ("http://test/api/upload_logs?version=1&hostname=testhost&"
       "request_hash=adcf29fb04666ade7b6379eb78e8ab709e95e566",
       {"agent": "smtp2web/1.0", "timeout": 30, "method": "POST",
        "headers": {"Content-Type": "text/csv"},
        "postdata": "test,smtp2web.com,10,foo@bar.com,test@smtp2web.com,123\r\n"
        "test,smtp2web.com,10,bleh@whatever.com,test@smtp2web.com,456\r\n"}, "", False),
      ("http://test/api/upload_logs?version=1&hostname=testhost&"
       "request_hash=d4922d449619456db4e6c2c22f5fca5ffd3946af",
       {"agent": "smtp2web/1.0", "timeout": 30, "method": "POST",
        "headers": {"Content-Type": "text/csv"},
        "postdata": ",testdomain.com,10,foo@bar.com,blah@testdomain.com,123\r\n"}, "", False)
    ])
    ret = self.settings.uploadLogs()
    ret.addCallback(lambda x: self.failUnlessEqual(self.settings.logentries, []))
    ret.addCallback(lambda x: self.settings.getPage.done())
    return ret

  def test_log_upload_error(self):
    """Tests handling of errors while uploading logs."""
    self.settings.logentries.append(
        ("test", "smtp2web.com", logging.DEBUG, "foo@bar.com",
         "test@smtp2web.com", 123))
    self.settings.getPage = FetcherMock(self, [
      ("http://test/api/upload_logs?version=1&hostname=testhost&"
       "request_hash=d0608d9c7b47543f0562c139a8d32a6ac85846ff",
       {"agent": "smtp2web/1.0", "timeout": 30, "method": "POST",
        "headers": {"Content-Type": "text/csv"},
        "postdata": "test,smtp2web.com,10,foo@bar.com,test@smtp2web.com,123\r\n"},
        failure.Failure(twisted.web.error.Error("500 Internal Server Error")), True)
    ])
    ret = self.settings.uploadLogs()
    ret.addCallback(lambda x: self.failUnlessEqual(len(self.settings.logentries), 1))
    ret.addCallback(lambda x: self.settings.getPage.done())
    return ret
