const util = require('util');
const redis = require('redis');

const client = redis.createClient('redis://localhost:6379');

module.exports = {
  getAsync: util.promisify(client.get).bind(client),
  delAsync: util.promisify(client.del).bind(client),
  setexAsync: util.promisify(client.setex).bind(client),
  incrAsync:  util.promisify(client.incr).bind(client),
  existsAsync: util.promisify(client.exists).bind(client),
};
