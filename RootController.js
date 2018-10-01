

function auth(username, password) {
  return new Promise((resolve) => {
    if (
      username === 'john.doe@example.com' &&
      password === 'example'
    ) return resolve(true);
    resolve(false);
  });
}

module.exports.post = async(req, res, next) => {
  try {
    let username = req.body.username;
    let password = req.body.password;
    
    const deviceCookie = req.deviceCookie;
    
    if (await req.deviceCookie.isLocked()) {
      return res.sendStatus(403);
    }

    if (!await auth(username, password)) {
      deviceCookie.detectDevice();
      return res.sendStatus(401);
    }

    await deviceCookie.detectDevice({trusted: true});
  
    res.status(200).json({
      decoded: deviceCookie.decoded,
      sessionId: req.sessionID
    });
  } catch (error) {
    next(error);
  }
};