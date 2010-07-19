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

from twisted.application import service
from twisted.application import internet
from twisted.enterprise import adbapi

import sys
import os
sys.path.append(os.path.dirname(__file__))

import smtp2web

application = service.Application("smtp2web Service")

settings = smtp2web.Settings(secret_key="",
                             state_file="state", master_host="www.s2w.m.ac.nz")

smtpServerFactory = smtp2web.ESMTPFactory(settings)
smtpServerService = internet.TCPServer(2025, smtpServerFactory)
smtpServerService.setServiceParent(application)
