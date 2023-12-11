# API method "check_message"
This page describes how API method "check_message" works

### Table of contents:
***
1. [Method description](#1-method-description)
2. [Request](#2-request)
    * [Data JSON Example](#data-json-example)
    * [Data Processing](#data-processing)
    * [Required Parameters](#required-parameters)
    * [Additional parameters](#additional-parameters)
3. [Response](#3-response)
   * [Response example](#response-example)
   * [Response explanation](#response-explanation)
   * [CleanTalk answer codes explanation](#cleantalk-answer-codes-explanation)
4. [Code examples](#4-code-examples)
   * [WGET](#using-wget)
   * [PHP](#using-php)
   * [NodeJS](#using-nodejs)
   * [C#](#using-c)
   * [GoLang](#using-golang)
5. [Related links](#5-related-links)
***

## 1. Method description
This method is the best to use on forms that contain User-generated content (UGC) like a comment, review, or contact form.

- Collect web-form data.
- Send data JSON via a POST request to https://moderate.cleantalk.org/api2.0.
- Parse the response and make a decision.

[^ Back to table of contents ^](#table-of-contents)
## 2. Request
### Data JSON Example
```json
{
"method_name":"check_message",
"auth_key":"your_acccess_key",
"sender_email":"stop_email@example.com",
"sender_nickname":"John Doe",
"sender_ip":"127.0.0.1",
"event_token":"sha_256_string_of_event_token",
"submit_time":15,
"sender_info": {
"REFERRER": "https:/referrer-site.com",
"USER_AGENT": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3835.0 Safari/537.36"
},
"tz":"UTC+01",
"phone":"+1237650009",
"message": "Hello I am a spammer visit this https://badlinkexample.com"
}
```
### Data Processing
> Necessary information about the data processing.

|Parameter| Explanation |
|-|------------|
|HTTP Method|POST|
|Data format|JSON|
|URL|	https://moderate.cleantalk.org/api2.0|

### Required Parameters
> These parameters are required.

|Parameter| Explanation                                                 |
|-|-------------------------------------------------------------|
|method_name| 	Must be "check_message".                                   |
|auth_key| 	Access key. To obtain a key please get an account [here](https://cleantalk.org/register) |
|sender_ip| 	IP you want to check for spam.                             |
|sender_email| 	Email of the sender.                                       |

### Additional parameters
> These parameters will improve filtration.

|Parameter| Explanation                                                                                                                                                                                                                             |
|-|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|all_headers| 	HTTP-request headers (JSON encoded).                                                                                                                                                                                                   |
|sender_nickname| 	Nickname you want to check for spam.                                                                                                                                                                                                   |
|sender_info| Information about the sender (JSON encoded). Include the next mandatory params: <br/> - **REFERRER**: the content of $_SERVER["HTTP_REFERER"] <br/> - **USER_AGENT**: the content of $_SERVER["HTTP_USER_AGENT"]                        |
|response_lang| 	API response language, use locale short string, like “EN”.                                                                                                                                                                             |
|tz| 	Sender's timezone.                                                                                                                                                                                                                     |
|phone| 	Sender's phone number.                                                                                                                                                                                                                 |
|event_token| 	The param is used to link all collected frontend data of the visitor with the request. This data is collected by the special script https://moderate.cleantalk.org/ct-bot-detector-wrapper.js that should be added to the page layout. |
|submit_time| 	Form submitting time in seconds.                                                                                                                                                                                                       |
|message| 	The visitor's message.  Will be checked for suspicious contacts, links, and many other conditions.                                                                                                                                     |

[^ Back to table of contents ^](#table-of-contents)

## 3. Response
### Response example
> The server's response is independent of the platform.
```json
{
"version" : "7.47",
"inactive" : 0,
"js_disabled" : 0,
"blacklisted" : 1,
"comment" : "*** Forbidden. Sender blacklisted. ***",
"codes" : "FORBIDDEN BL",
"fast_submit" : 0,
"id" : "5a49267e202169b3a4d9ddefee190065",
"account_status" : 1,
"allow" : 0
}
```
### Response Explanation
| Key            | Explanation                                                                   |
|----------------|-------------------------------------------------------------------------------|
| js_disabled    | 	JavaScript is disabled or not (1/0)                                          |
| blacklisted    | 	The sender is in the CleanTalk Blacklists.                                   |
| comment        | 	Comment on the server's decision or on other errors (wrong Access key etc.). |
| fast_submit    | 	If forms were submitted too often.                                           |
| id             | 	Message ID (helpful for our support).                                        |
| account_status | 	Is the account enabled or not (1/0).                                         |
| allow          | 	Is message allowed or not (1/0).                                             |
| codes          | Server answer codes. Could be from the list below.                            |

#### CleanTalk answer codes explanation

| Code                       | Explanation                                                |
|----------------------------|------------------------------------------------------------| 
| ALLOWED                    | Allowed                                                    |
| ALLOWED_PRIV_LIST          | Private list allow                                         |
| ALLOWED_PROFILE            | Profile allowed                                            |
| ALLOWED_USER               | User allowed                                               |
| BAD_INSTALL                | Check plugin setup                                         |
| BAD_LANGUAGE               | Contains bad language                                      |
| BL_DOMAIN                  | HTTP links blacklisted                                     |
| BL                         | Sender blacklisted                                         |
| COMMENT_TYPE_UNKNOWN       | Trackback, Pingback comment's type needs manual moderation |
| CONTACTS                   | Contains links                                             |
| CONTACTS_DATA              | Contains contacts                                          |
| DENIED                     | Forbidden                                                  |
| DENIED_GREY_LIST           | Please submit the form again                               |
| DENIED_PRIV_LIST           | Private list deny                                          |
| DENIED_PROFILE             | Profile forbidden                                          |
| DENIED_USER                | User forbidden                                             |
| ERR_CLIENT_IP_EQ_SERVER_IP | Site visitor IP is equal to server site IP                 |
| FAST_SUBMIT                | Submitted too quickly                                      |
| FORBIDDEN                  | Forbidden                                                  |
| JS_DISABLED                | Please enable JavaScript                                   |
| KEY_NOT_FOUND              | “Anti-Spam disabled. Check the Access key                  |
| MANUAL                     | Need manually approved                                     |
| MULT_MESSAGE               | Massive posting                                            |
| MULT_SUBMIT                | Multiple comments submitted                                |
| NO_NORM_WORDS              | Without dictionary words                                   |
| OFFTOP                     | Off-topic                                                  |
| SERVICE_DISABLED           | Service disabled. Check account status                     |
| SERVICE_FREEZED            | Service froze. Please extend the limit                     |
| STOP_LIST                  | Contains stop words                                        |
| TRIAL_EXPIRED              | The trial period expired                                   |
| USERNAME_SPAM              | Spam sender name                                           |
| WRONG_TZ                   | Wrong time zone                                            |
| EMAIL_NOT_EXISTS           | The E-mail address does not exist                          |
| BL_EMAIL                   | E-mail blacklisted                                         |
| BL_IP                      | IP address blacklisted                                     |
| SEEMS_SPAM_EMAIL           | E-mail contains spam templates                             |
| SEEMS_SPAM_HEADERS         | HTTP-request headers look like a spam bot                  |
| SEEMS_SPAM_MESSAGE         | Message contains spam templates                            |
| SEEMS_SPAM_NICK            | Nickname contains spam templates                           |
| EMAIL_DOMAIN_NOT_EXISTS    | The E-mail domain does not exist                           |

* The rest are information flags for displaying appropriate messages to site visitors.
* In the server response code, you can also see the result of checking an email address for existence. If a blocked request contains a non-existent e-mail address, you will see the next text in the API response code field: "FORBIDDEN EMAIL_NOT_EXISTS"
* Please note, that this code will be displayed only if a non-existent email is the main reason for blocking.

[^ Back to table of contents ^](#table-of-contents)

## 4. Code Examples
### Using Wget
#### CLI example
```text
wget -O- --post-data='{"method_name":"check_newuser","auth_key":"your_acccess_key","sender_email":"stop_email@example.com","sender_nickname":"John Doe","sender_ip":"127.0.0.1","js_on":1,"submit_time":15}' https://moderate.cleantalk.org/api2.0
```
### Using PHP
Download the CleanTalk library here. The library folder must be placed in the same path as the PHP file. Also, you can install the library via Composer.

#### PHP backend
```php
<?php

use Cleantalk\Cleantalk;
use Cleantalk\CleantalkRequest;

session_start();

require_once (dirname(__FILE__) . '/lib/Cleantalk.php');
require_once (dirname(__FILE__) . '/lib/CleantalkRequest.php');
require_once (dirname(__FILE__) . '/lib/CleantalkResponse.php');
require_once (dirname(__FILE__) . '/lib/CleantalkHelper.php');

// Take params from config
$config_url = 'http://moderate.cleantalk.org/api2.0/';
$auth_key = 'your_key';// Set Cleantalk auth key

if (count($_POST))
{
    $sender_nickname = 'John Dow';
    if (isset($_POST['login']) && $_POST['login'] != ''){
        $sender_nickname = $_POST['login'];
    }

    $sender_email = 'stop_email@example.com';
    if (isset($_POST['email']) && $_POST['email'] != '') {
        $sender_email = $_POST['email'];
    }

    $sender_ip = null;
    if (isset($_SERVER['REMOTE_ADDR'])) {
        $sender_ip = $_SERVER['REMOTE_ADDR'];
    }

    // The facility in which to store the query parameters
    $ct_request = new CleantalkRequest();
    $ct_request->auth_key = $auth_key;
    $ct_request->agent = 'php-api';
    $ct_request->sender_email = $sender_email;
    $ct_request->sender_ip = $sender_ip;
    $ct_request->sender_nickname = $sender_nickname;
    $ct_request->event_token = isset($_POST['ct_bot_detector_event_token'])
        ? $_POST['ct_bot_detector_event_token']
        : null;
    $ct_request->message = isset($_POST['message_field'])
        ? $_POST['message_field']
        : null;
    $ct_request->submit_time = isset($_SESSION['ct_submit_time'])
        ? time() - (int) $_SESSION['ct_submit_time']
        : null;
    // you can change comment type to "general_contact_form" to make the check more specified
    $ct_request->post_info = '{"comment_type":"general_comment"}';

    //Additional parameters.
    $ct = new Cleantalk();
    $ct->server_url = $config_url;

    //Check
    $ct_result = $ct->isAllowMessage($ct_request);
    if ($ct_result->allow == 1) {
        echo 'User allowed. Reason ' . $ct_result->comment;
    } else {
        echo 'User forbidden. Reason ' . $ct_result->comment;
        echo '<br /><br />';
    }
}
else {
    $_SESSION['ct_submit_time'] = time();
}
```

> The submit_time and event_token parameters are very important for checking. See the desrciption of additional parameters.

#### HTML frontend
```html
<?php session_start(); $_SESSION['ct_submit_time'] = time();?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Title</title>
    <script src="https://moderate.cleantalk.org/ct-bot-detector-wrapper.js"></script>
</head>
<body>
<form method="post" action="check_message.php">
    <label for="login">Your name</label>
    <input type="text" name="login" id="login" /> <br />
    <label for="email">Your email:</label>
    <input type="text" name="email" id="email" value="" /> <br />
    <label for="message_field">Enter your message:</label>
    <textarea name="message_field" id="message_field"></textarea> <br />
    <input type="submit" />
</form>
</body>
</html>
```
#### Example of additional parameters usage
```php
$sender_info = array(
        'page_url' =>htmlspecialchars(@$_SERVER['SERVER_NAME'].@$_SERVER['REQUEST_URI']),
        'REFFERRER' => htmlspecialchars(@$_SERVER['HTTP_REFERER']),
        'USER_AGENT' => htmlspecialchars(@$_SERVER['HTTP_USER_AGENT']),
        'fields_number' => sizeof($_POST),
);
$sender_info = json_encode($sender_info);
        if ($sender_info === false) $sender_info = '';
$ct_request->sender_info = $sender_info;
$ct_request->phone = '+1 123-456-78-90';
$ct_request->all_headers = json_encode(apache_request_headers());
```
> More info can be found on our [GitHub](https://github.com/CleanTalk/php-antispam).

### Using Python
#### Python Backend (Django)
Example of CleanTalk class implementation. Place the code in a file (something like cleantalk.py) and import the module to the code where you need to use it.
```python
#!/usr/bin/python
# coding=utf-8

from __future__ import unicode_literals

try:
from urllib.request import urlopen, Request
from urllib.parse import urlparse
from urllib.parse import urlencode
import os

except ImportError:
from urllib import urlopen, Request, urlencode
from urlparse import urlparse
import os

import json


class CleanTalk:
"""Python API for CleanTalk.org"""
VERSION = 1.2
ENCODING = 'utf-8'
user_agent = 'Mozilla/5.0'

    def __init__(self,
                 auth_key,
                 method_name,
                 server_url='https://moderate.cleantalk.org',
                 api_url='/api2.0',
                 connection_timeout=8,
                 agent=None):

        """
        This method constructs a new CleanTalk object and returns it.
        :param auth_key:
        :param server_url:
        :param api_url:
        :param connection_timeout:
        :param method_name:
        """
        self.__server_url = server_url
        self.__api_url = api_url
        self.__connection_timeout = connection_timeout
        self.__method_name = method_name
        self.__auth_key = auth_key
        if agent:
            self.__agent = agent
        else:
            self.__agent = 'python-api-' + str(CleanTalk.VERSION)

    def request(self,
                sender_email,
                message='',
                sender_ip='',
                sender_nickname='',
                js_on=1,
                post_info=None,
                sender_info=None,
                submit_time=None,
                event_token=None):
        """
        This method will dispatch call to servers.
        Exceptions can be raised: ValueError on bad json, URLError on bad url, HTTPError, HTTPException on http-error
        :param sender_email: Required. Email IP of the visitor.
        :param message: Visitor's message if applicable.
        :param sender_ip: IP address of the visitor. You can skip this field if event_token is provided.
        :param sender_nickname: Nickname of the visitor
        :param js_on: if javascript is enabled on visitors side
        :param sender_info: additional sender info
        :param submit_time: the time from page start to submit event
        :param post_info: info about the page
        :param event_token: token for check data from frontend
        :return: dictionary, where:
                    KEY                     VALUE
                -----------             --------------------
                allow                   0|1 - spam or not comment/registration
                id                      MD5_HEX - unique request ID
                comment                 string - description about request from server
                stop_queue              0|1 - should comment move to site's moderation queue or not
                inactive                0|1 - should registration move to inactive state or not
        """
        if sender_info is None:
            sender_info = {}
        if post_info is None:
            post_info = {}
        if submit_time is None:
            submit_time = '100'

        url = self.__server_url + self.__api_url
        headers = {'User-Agent': self.user_agent,
                   'content-type': 'application/json; encoding=utf-8'}

        values = {
            'auth_key': self.__auth_key,
            'message': message,
            'sender_ip': sender_ip,
            'sender_email': sender_email,
            'sender_nickname': sender_nickname,
            'js_on': js_on,
            'agent': self.__agent,
            'post_info': post_info,
            'sender_info': sender_info,
            'submit_time': submit_time,
            'event_token': event_token
        }
        data = json.dumps(values, separators=(',', ':'))
        request = Request(url, data.encode(CleanTalk.ENCODING), headers)
        response = urlopen(request, timeout=self.__connection_timeout)
        response_bytes = response.read()
        response_str = response_bytes.decode(CleanTalk.ENCODING)
        response_parsed = json.loads(response_str)

        return response_parsed


def cleantalk_check_message(form_message,
form_sender_email,
form_sender_nickname='',
form_ip='',
form_event_token='',
form_submit_time='',
post_info=None,
sender_info=None):
"""
API method "check_message" wrapper. Do check params and return result.
:param str form_message: Required. Message field from HTML form.
:param str form_sender_email: Required. Message field from HTML form.
:param str form_sender_nickname: Message field from HTML form.
:param str form_ip: Visitor's IP address
:param str form_event_token: Bot detector event token field from HTML form.
:param int form_submit_time: The time passed from page start to submit event.
:param object post_info: Additional page info.
:param object sender_info: Additional sender info.
:return: object: {
'result': '%1 if allowed, 0 if denied%',
'comment': '%comment from cleantalk server%'
}
"""

    # Init CleanTalk class object.

    ct = CleanTalk(
        auth_key=os.getenv('CLEANTALK_TEST_API_KEY'),
        method_name='check_message',
        server_url='https://moderate.cleantalk.org',
        api_url='/api2.0',
        connection_timeout=8,
        agent=None
    )

    # Run API request.

    ct_result = ct.request(
        message=form_message,
        sender_ip=form_ip,
        sender_email=form_sender_email,
        sender_nickname=form_sender_nickname,
        js_on=1,
        event_token=form_event_token,
        post_info=json.dumps(post_info),
        sender_info=json.dumps(sender_info),
        submit_time=form_submit_time
    )

    # Handle results.

    if ct_result['allow']:
        return {'result': 1, 'comment': ct_result['comment']}
    else:
        return {'result': 0, 'comment': ct_result['comment']}
```
#### Example of Django View code:
```python
class ERegisterView(View):
template_name = 'register.html'

    def get(self, request, *args, **kwargs):
        context = {}
        context.update(csrf(request))
        context['register_form'] = RegisterForm()
        return render(None, template_name=self.template_name, context=context)

    def post(self, request, *args, **kwargs):
        context = {}
        form = RegisterForm(request.POST)
        if form.is_valid():
            post_data = request.POST
            # run the check
            check_result = cleantalk_check_newuser(form_sender_email=post_data['email'],
                                                   form_sender_nickname=post_data['name'],
                                                   form_ip='199.1.2.3',
                                                   form_event_token=post_data['ct_bot_detector_event_token'])
            if not check_result['result']:
                context['is_spam'] = 1
                context['ct_comment'] = check_result['comment']

        return render(None, template_name=self.template_name, context=context)
```
#### Example of Django template to be used in the form view:
```python
{% load django_bootstrap5 %}
{% bootstrap_css %}
{% bootstrap_javascript %}
{% bootstrap_messages %}

{% block page %}
<h1>Registration</h1>
<article>
{% if register_form %}
<p>Welcome!</p>
<p>Please, register us via the form below.</p>
<form id="register_form" action="{% url 'blog:register' %}" method="post">
{% csrf_token %}
{% bootstrap_form register_form %}
<button type="submit">SEND</button>
</form>
{% elif is_spam %}
<p>Seems to be spam: {{ct_comment}}</p>
{% else %}
<p>Success.</p>
{% endif %}
</article>
{% comment %}
Comment: Add Bot-detector JS script to send visitor's frontend params. This script do next:
1. Collect frontend data and send them to the cloud directly from script.
2. Adds the ct_bot_detector_event_token field to all the forms on the page. This token used to compare backend
POST data and cloud data got from script.
{% endcomment %}
<script src="https://moderate.cleantalk.org/ct-bot-detector-wrapper.js" id="ct_bot_detector-js"></script>
{% endblock %}
```

### Using NodeJS
#### Backend (Express.js)
1. Include CleanTalk javascript code to your website template into <head> block to appear on every page.

<script src="https://moderate.cleantalk.org/ct-bot-detector-wrapper.js" id="ct_bot_detector-js"></script>
2. Install the CleanTalk dependency.

```text
npm install cleantalk
```
3. Include the cleantalk middleware in your app.

4. Define the access key in your environment.

5. Collect the data to send to the CleanTalk cloud. See the format

6. Add the CleanTalk middleware to the route that needs to be anti-spam protected.

```js
const express = require('express');
const app = express();
// 1) Include the cleantalk middleware to youe app
const CleantalkMiddleware = require("cleantalk/src/middlewares/express");

// 2) Define the acces key in your environment
const auth_key = process.env.CLEANTALK_AUTH_KEY || null;

// 3)Collect the data to send to the cleantalk cloud.
const sender_info = {
sender_email: 'body.sender_email',
sender_nickname: 'body.sender_nickname',
message: 'body.message',
};

// 4) Add the cleantalk middleware to the route need to be anti-spam protected
app.post('/form', CleantalkMiddleware(auth_key, 'message', sender_info), (req, res) => {
if ( ! req.cleantalkDecision.isAllowed ) {
res.send({message: req.cleantalkDecision.comment} );
}
res.send({});
});
```

### Using C#
> The CleanTalk team would be grateful for your possible participation in the implementation of a detailed example for this language. If you would like to take part, please contact us via plugins@cleantalk.org

#### Backend (.NET)
1. Download the package from GitHub: https://github.com/CleanTalk/csharp-antispam
2. Add the relation link to the cleantalk.csharp package in your project.
3. See existing test cases for example:

```c
public const string AuthKey = "auth key";

[TestFixture]
public class CheckMessageTests
{
private ICleantalk _cleantalk;

    [Test]
    public void NotSpamMessageTest()
    {
        var req1 = new CleantalkRequest(AuthKey)
        {
            Message = "This is a great storm!", //get this form the web form
            SenderInfo = new SenderInfo
            {
                Refferrer = "https://www.bbc.co.uk/sport",
                UserAgent = "Opera/9.80 (Windows NT 6.1; WOW64) Presto/2.12.388 Version/12.12"
            },
            SenderIp = "91.207.4.192",
            SenderEmail = "keanu8dh@gmail.com", /get this form the web form
            SenderNickname = "Mike", /get this form the web form
            //IsJsEnable = 1, redundant if use event_token
            EventToken = "f32f32f32f32f32f32f32f32f32f32a2",
            ///     To get this param:
            ///         1. add a script to the web-page: <script src="https://moderate.cleantalk.org/ct-bot-detector-wrapper.js" id="ct_bot_detector-js"></script>
            ///         2. parse the newly added hidden input on the web form, the name atrribute of input is "ct_bot_detector_event_token"
            ///     @var string

            SubmitTime = 15
        };

        Debug.WriteLine("req1=" + WebHelper.JsonSerialize(req1));
        var res1 = _cleantalk.CheckNewuser(req1);
        Debug.WriteLine("res1=" + WebHelper.JsonSerialize(res1));
        Assert.IsNotNull(res1);
        Assert.IsNotNullOrEmpty(res1.Id);
        Assert.AreEqual(0, res1.IsInactive);
        Assert.IsTrue(res1.IsAllow.GetValueOrDefault());
        Assert.IsNotNullOrEmpty(res1.Comment);
    }
}
```
#### Frontend (HTML)
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Title</title>
    <script src="https://moderate.cleantalk.org/ct-bot-detector-wrapper.js" id="ct-bot-detector-js></script>
</head>
<body>
  <form method="post" action="chek_newuser.php">
      <label for="login">Login:</label>
      <input type="text" name="login" id="login" /> <br />
      <label for="email">Email:</label>
      <input type="text" name="email" id="email" value="" /> <br />
      <label for="login">Message:</label>
      <input type="text" name="message" id="message" /> <br />
      <input type="submit" />
  </form>
</body>
</html>
```

### Using GoLang
```golang
package main

import (
"encoding/json"
"fmt"
"io"
"io/ioutil"
"net/http"
"strings"
)

var authKey string = "enter_your_key"
var configUrg string = "http://moderate.cleantalk.org/api2.0/"
var agent string = "golang-api"

type messageInputData struct {
MethodName     string `json:"method_name"`
AuthKey        string `json:"auth_key"`
Agent          string `json:"agent"`
SenderEmail    string `json:"sender_email"`
SenderIp       string `json:"sender_ip"`
SenderNickname string `json:"sender_nickname"`
JsOn           uint   `json:"js_on"`
SubmitTime     uint   `json:"submit_time"`
AllHeaders     string `json:"all_headers"`
Message        string `json:"message"`
SenderInfo     string `json:"sender_info"`
ResponseLang   string `json:"response_lang"`
PostInfo       string `json:"post_info"`
StoplistCheck  uint   `json:"stoplist_check"`
}

type MessageResultData struct {
Version       string `json:"version"`
Inactive      uint   `json:"inactive"`
JsDisabled    uint   `json:"js_disabled"`
Blacklisted   string `json:"blacklisted"`
Comment       string `json:"comment"`
Codes         string `json:"codes"`
FastSubmit    uint   `json:"fast_submit"`
Id            string `json:"id"`
AccountStatus uint   `json:"account_status"`
Allow         uint   `json:"allow"`
StopQueue     uint   `json:"stop_queue"`
Spam          uint   `json:"spam"`
}

func main() {
inputData := messageInputData{
MethodName:     "check_message",
AuthKey:        authKey,
Agent:          agent,
SenderEmail:    "stop_email@example.com",
SenderIp:       "192.168.0.1",
SenderNickname: "testuser",
JsOn:           1,
SubmitTime:     5,
Message:        "Test message",
}

resultData, err := CheckMessage(inputData)
if err != nil {
fmt.Println(err.Error())
return
}
if resultData.Allow == 1 {
fmt.Println(fmt.Sprintf("User allowed. Reason %s", resultData.Comment))
return
}
fmt.Println(fmt.Sprintf("User forbidden. Reason %s", resultData.Comment))
}

func CheckMessage(inputData messageInputData) (MessageResultData, error) {
inputDataBytes, err := json.Marshal(inputData)
var resultData MessageResultData
if err != nil {
return resultData, err
}
var body io.Reader = strings.NewReader(string(inputDataBytes))
req, err := http.NewRequest(http.MethodPost, configUrg, body)
if err != nil {
return resultData, err
}
req.Header.Set("Content-Type", "application/json")

client := &http.Client{}
resp, err := client.Do(req)
if err != nil {
return resultData, err
}
defer resp.Body.Close()

answer, err := ioutil.ReadAll(resp.Body)
if err != nil {
return resultData, err
}
err = json.Unmarshal(answer, &resultData)
return resultData, nil

}
```
## 5. Related Links
### Available features related to the method:
* [CleanTalk's Personal Blacklist or Whitelist](https://cleantalk.org/help/blacklist-usage) feature helps you to block unwanted users and to allow users that were recognized as spammers.
* The [Stop-Word](https://cleantalk.org/help/stop-word) feature allows you to block comments and nicknames that contain any word from your Stop-Word List.
* [Country Blacklist](https://cleantalk.org/help/extra-package#country_blacklist) allows you to block all comments and registration coming from selected countries.
* Stop-Word and Country Blacklist features are available after purchasing our [Extra Package](https://cleantalk.org/help/extra-package). Go to your [Renewal License Page](https://cleantalk.org/my/bill/recharge) to see the details.

[^ Back to table of contents ^](#table-of-contents)
