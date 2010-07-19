smtp2web
========

This is a fork of [smtp2web][s], the original can be found on
[google code][g].

There are two major differences between this version and the
original:

1. This version does not require you to confirm ownership
   of the URL being posted to. I choose to run this version
   with Google Apps authentication instead.
   
2. This version parses the e-mail and posts, using ordinary
   form encoding, the e-mail. You get the headers and all
   content parts, with all the pesky e-mail encoding done
   for you.

[s]: http://www.smtp2web.com/
[g]: http://code.google.com/p/smtp2web

What you need to do to run this:

1. You'll need to get setup with [Google appengine][ga],
   create an app, and set that app ID in admin/app.yaml
   Set the path for your app (e.g. my-cool-smtp2web.appspot.com)
   in server/smtpserver.tac

2. You'll need a server with port 25 accessible.

3. Setup MX records for your domain that you want it 
   to accept mail for. Then set this in admin/controllers/mapping.py
   on line 25 where it currently says s2w.m.ac.nz
   
4. You'll need to create entries for each server you want to run the
   smtpd on in admin/controllers/api.py, in the final function - AddSmtpHost#get:
    
    s = model.SmtpServer(hostname="hostname.as.reported.by.your.server",mxname="Testing",secret_key="key")
    s.put()
  
   Add one for each, and pet the secret_key you specify here in server/smtpserver.tac

5. Push the admin app to appengine (see [google documentation][gd])

6. Set the user your smtpd will run as - in admin/runserver.sh change -u patrick to -u youruser, and change
   log and PID paths - the defaults may work for you, if you choose to deploy in /usr/local/smtp2web

7. Start the smtpd on your servers, change to the directory where it is running, and as root run ./runserver.sh

8. Go to the admin interface, e.g. http://my-cool-smtp2web.appspot.com/ and add a mapping, and give it a go!

[ga]: http://code.google.com/appengine/
[gd]: http://code.google.com/appengine/docs/python/tools/uploadinganapp.html

Licence
-------

Copyright 2008 arachnid AT notdot.net,
          2010 Patrick Quinn-Graham

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.