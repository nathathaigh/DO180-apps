var createError = require('http-errors');  // fix: http-error → http-errors

var express = require('express');
var app = express();                        // fix: added 'var' to avoid global variable

app.get('/', function (req, res) {
  res.send('Hello World from pod: ' + process.env.HOSTNAME + '\n');  // fix: process.environment → process.env
});

app.listen(8080, function () {
  console.log('Example app listening on port 8080!');
});
