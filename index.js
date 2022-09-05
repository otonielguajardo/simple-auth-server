const express = require('express');
const cors = require('cors');
const morgan = require("morgan");
const helmet = require("helmet");
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const uuid = require('uuid');
const port = process.env.PORT || 8080;

// simulates database tables
const users = [
  { id: 1, email: "user1", password: "pass1" },
  { id: 2, email: "user2", password: "pass2" },
];
const sessions = {};
const cookieConfig = (expiresAt) => {
  return {
    secure: true,
    httpOnly: false,
    sameSite: 'None',
    expires: expiresAt
  };
};

class Session {
  constructor(email, expiresAt) {
    this.email = email;
    this.expiresAt = expiresAt;
  }

  isExpired() {
    this.expiresAt < (new Date());
  }
}

const loginHandler = (req, res) => {

  const { email, password } = req.body
  if (!email) {
    res.status(401).end();
    return;
  }

  const currentUser = users.find((user) => {
    return user.password === password && user.email === email;
  });

  if (currentUser == undefined) {
    res.status(401).end();
    return;
  }

  // random UUID as session token
  const sessionToken = uuid.v4();

  // set the expiry time as 120s after the current time
  const now = new Date();
  const expiresAt = new Date(+now + 120 * 1000);

  // create a session containing information about the user and expiry time
  const session = new Session(email, expiresAt);

  // add the session information to sessions map
  sessions[sessionToken] = session;

  // set a cookie on response
  res.cookie("session_token", sessionToken, cookieConfig(expiresAt));
  res.json(currentUser).end();
}

function authMiddleware(req, res, next) {
  // if request has no cookies return unauthorized
  if (!req.cookies) {
    res.status(401).end();
    return;
  }

  // get session_cookies from request, if not set return unauthorized
  const sessionToken = req.cookies['session_token'];
  if (!sessionToken) {
    res.status(401).end();
    return;
  }

  // get session from session map, if not present return unauthorized
  userSession = sessions[sessionToken];
  if (!userSession) {
    res.status(401).end();
    return;
  }

  // if session expired, return unauthorized and delete session from our map
  if (userSession.isExpired()) {
    delete sessions[sessionToken];
    res.status(401).end();
    return;
  }

  // if all checks passed user is authenticated
  next();
}

const meHandler = (req, res) => {
  const currentUser = users.find((user) => {
    return user.email === userSession.email;
  });
  res.json(currentUser).end();
}

const refreshHandler = (req, res) => {
  // new token
  const newSessionToken = uuid.v4();

  // renew the expiry time
  const now = new Date();
  const expiresAt = new Date(+now + 120 * 1000);
  const session = new Session(userSession.email, expiresAt);

  // add new session to map, and delete old session
  sessions[newSessionToken] = session;
  delete sessions[req.cookies['session_token']];

  // set new cookie on response
  res.cookie("session_token", newSessionToken, cookieConfig(expiresAt));
  res.end();
}

const logoutHandler = (req, res) => {
  // delete session from map
  delete sessions[req.cookies['session_token']];

  // expire cookie and return empty value for session_token
  res.cookie("session_token", "", cookieConfig(new Date()));
  res.end();
}

const app = express();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());

app.use(function (req, res, next) {
  res.header("Access-Control-Allow-Credentials", true);
  res.header("Access-Control-Allow-Origin", req.headers.origin);
  res.header(
    "Access-Control-Allow-Methods",
    "GET,PUT,POST,DELETE,UPDATE,OPTIONS"
  );
  res.header(
    "Access-Control-Allow-Headers",
    "X-Requested-With, X-HTTP-Method-Override, Content-Type, Accept"
  );
  next();
});

// app.use(
//   cors({
//     allowedHeaders: "*",
//     allowMethods: "*",
//     allowOrigin: "*",
//     origin: "*",
//   })
// );
app.use(morgan("dev"));
app.use(helmet());
app.use(express.json());

app.post('/auth/login', loginHandler);
app.post('/auth/logout', [authMiddleware], logoutHandler);
app.post('/auth/refresh', [authMiddleware], refreshHandler);
app.get('/auth/me', [authMiddleware], meHandler);
app.get("/", function (req, res) {
  res.send("Auth server working");
});

app.listen(port, function () {
  console.log(`Auth server available on http://localhost:${port}`);
});