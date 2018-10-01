const util = require('util');
const redis = require('redis');
const commands = require('redis-commands');

const client = redis.createClient('redis://localhost:6379');

module.exports = Object.assign({ client }, commands.list.reduce((api, command) => {
  // Some rare Redis commands use special characters in their command name
  // Convert those to a underscore to prevent using invalid function names
  var commandName = command.replace(/(?:^([0-9])|[^a-zA-Z0-9_$])/g, '_$1');
  
  api[`${commandName}Async`] = util.promisify(client[commandName]).bind(client);
  return api;
}, { /* api object */ }));
