const crypto = require('crypto');
const jsonwebtoken = require('jsonwebtoken');
const mm = require('micromatch');
const redis = require('./redis');

class DeviceCookie {
  constructor(req, config) {
    this.req = req;
    this.token = null;
    this.trusted = false;
    this.decoded = null;
    this.disabled = config.disabled;
  }

  async generate(subject, trusted) {
    this.token = await this.generateToken(subject, trusted);
    this.decoded = await this.decode(this.token);
    return this.token;
  }

  generateToken(subject, trusted=false) {
    return new Promise((resolve, reject) =>{
      jsonwebtoken.sign({
        trst: trusted
      }, 'very_secret', {
        audience: 'device-cookie',
        jwtid: crypto.randomBytes(25).toString('hex'),
        subject
      }, (error, token) => {
        if (error) return reject(error);
        this.trusted = trusted;
        this.token = token;
        resolve(token);
      });
    });
  }
  
  decode(token) {
    return new Promise((resolve, reject) => {
      jsonwebtoken.verify(token, 'very_secret', {
        audience: 'device-cookie'
      }, (error, decoded) => {
        if (error) return reject(error);
        this.trusted = decoded.trst;
        resolve(decoded);
      });
    });
  }
  
  isLocked() {
    return new Promise(async(resolve) => {
      if (this.trusted) return resolve(false);
      const attempts = Number(await redis.getAsync(`device:lock:${this.decoded.sub}`));
      resolve(attempts >= 10);
    });
  }
  
  markAsUntrusted(username) {
    return new Promise(async(resolve) => {
      if (!await redis.existsAsync(`device:lock:${username}`)) {
        await redis.setexAsync(`device:lock:${username}`, 3600, 0);
      }
  
      await redis.incrAsync(`device:lock:${username}`);
      resolve(true);
    });
  };
  
  unlockDevice(username) {
    return new Promise(async(resolve) => {
      await redis.delAsync(`device:lock:${username}`);
      resolve();
    });
  }

  async readFromResponse() {
    if (this.req.session) {
      this.token = this.req.session.deviceCookie;
    }
    this.decoded = this.token ? await this.decode(this.token) : null;
  }

  async detectDevice(options = {}) {
    if (options.trusted || this.decoded.trst) {
      // unlock device if it was locked
      await this.unlockDevice(this.decoded.sub);
      // generate trusted token
      await this.generate(this.decoded.sub, true);
      // replace request token with a trusted one
      this.req.session.deviceCookie = this.token;
    } else {
      await this.markAsUntrusted(this.decoded.sub);
    }
  }
}

const defaultConfig = {
  disabled: false,
  includePath: []
};

module.exports = (config = defaultConfig) => {
  return async(req, res, next) => {
    req.deviceCookie = new DeviceCookie(req, config);

    if (
      config.disabled ||
      !mm.any(req.path, config.includePath)
    ) return next();

    await req.deviceCookie.readFromResponse();
    
    const username = req.body.username;

    if (!req.deviceCookie.token || req.deviceCookie.decoded.sub !== username) {
      await req.deviceCookie.generate(username, false);  
    }
    
    req.session.deviceCookie = req.deviceCookie.token;

    next();
  }
};