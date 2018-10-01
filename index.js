const http = require('http');
const express = require('express');
const session = require('express-session');
const getid = require('uuid/v4');

const DeviceCookie = require('./DeviceCookie');
const RootController = require('./RootController');

const app = express();

app.use(session({
  name: 'did',
  genid: () => getid(),
  resave: false,
  saveUninitialized: false,
  secret: 'secret',
  proxy: true,
  cookie: {
    maxAge: 182 * 24 * 60 * 60 * 1000,
    secure: process.env.NODE_ENV === 'production'
  }
}));

app.use(express.json());
app.use(DeviceCookie({
  disabled: false,
  includePath: ['/']
}));

app.post('/', RootController.post);

app.use((error, req, res, next) => {
  console.log(error);
  res.sendStatus(500);
})

const server = http.createServer(app);
server.listen(3000, () => {
  console.log('Server is listening on port 3000');
});