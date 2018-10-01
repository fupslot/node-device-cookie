const crypto = require('crypto');
const jsonwebtoken = require('jsonwebtoken');
const mm = require('micromatch');
const redis = require('./redis');

class DeviceCookie {
  constructor(req, config={}) {
    this.req = req;
    this.token = null;
    this.trusted = false;
    this.decoded = null;
    this.timePeriodMS = config.timePeriodMS || 60 * 60 * 1000;
    this.maxAttempts = config.maxAttempts || 10;
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
      const attempts = Number(await redis.hgetAsync(`device:${this.decoded.sub}`, 'attempts'));
      
      const locked = attempts >= this.maxAttempts;
      if (locked) {
        await redis.hsetAsync(`device:${this.decoded.sub}`, 'lockedAt', (new Date()));
        await redis.hsetAsync(`device:${this.decoded.sub}`, 'ip', this.req.ip);
        // destroy untrust session
        await (new Promise((res) => this.req.session.destroy(res)));
      }

      resolve(locked);
    });
  }
  
  markAsUntrusted(username) {
    return new Promise(async(resolve) => {
      if (!await redis.existsAsync(`device:${username}`)) {
        await redis.hsetAsync(`device:${username}`, 'attempts', 0);
        await redis.expireAsync(`device:${username}`, this.timePeriodMS / 1000);
      }
  
      await redis.hincrbyAsync(`device:${username}`, 'attempts', 1);
      resolve(true);
    });
  };
  
  unlockDevice(username) {
    return new Promise(async(resolve) => {
      await redis.delAsync(`device:${username}`);
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
      const sess = await redis.getAsync(`device:lastsess:${this.decoded.sub}`);
      if (sess) await redis.delAsync(`sess:${sess}`);
      await redis.setAsync(`device:lastsess:${this.decoded.sub}`, this.req.session.id);
    } else {
      await this.markAsUntrusted(this.decoded.sub);
      // destroy untrust session
      await (new Promise((res) => this.req.session.destroy(res)));
    }
  }
}

const defaultConfig = {
  includePath: []
};

module.exports = (config=defaultConfig) => {
  return async(req, res, next) => {
    req.deviceCookie = new DeviceCookie(req, config);

    if (!mm.any(req.path, config.includePath)) return next();

    await req.deviceCookie.readFromResponse();
    
    const username = req.body.username;

    if (!req.deviceCookie.token || req.deviceCookie.decoded.sub !== username) {
      await req.deviceCookie.generate(username, false);  
    }
    
    req.session.deviceCookie = req.deviceCookie.token;

    next();
  }
};