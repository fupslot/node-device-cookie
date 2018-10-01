const http = require('http');
const express = require('express');
const session = require('express-session');
const RedisStore = require('connect-redis')(session);

const DeviceCookie = require('./DeviceCookie');
const RootController = require('./RootController');
const redis = require('./redis');

const app = express();

app.use(session({
  store: new RedisStore({ client: redis.client }),
  name: 'did',
  resave: false,
  saveUninitialized: false,
  secret: 'secret',
  proxy: true,
  cookie: {
    maxAge: 30 * 24 * 60 * 60 * 1000,
    secure: process.env.NODE_ENV === 'production'
  }
}));

app.use(express.json());
app.use(DeviceCookie({
  timePeriodMS: 60 * 60 * 1000,
  maxAttempts: 10,
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