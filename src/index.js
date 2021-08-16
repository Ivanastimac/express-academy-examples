// Load environment variable from .env file if not supplied
const path = require('path');
require('dotenv').config({
  path: (typeof process.env.DOTENV_PATH !== 'undefined')
    ? path.resolve(process.cwd(), process.env.DOTENV_PATH)
    : path.resolve(process.cwd(), '.env'),
});

const express = require('express')
const morgan = require('morgan');
const jwtExpress = require('express-jwt');
const jwt = require('jsonwebtoken');

const pretty = require('./utils/pretty');
const { ERROR_PAGE_NOT_FOUND, errorDescriptor } = require('./errors');
const { customCORSAndAuthErrorMiddleware } = require('./utils/customMiddleware');
const loadPrivateKey = require('./utils/loadPrivateKey');


const {
  certPrivate,
  certPublic,
} = loadPrivateKey();

const app = express()


app.use(morgan('combined'));

app.get('/', (req, res) => {
  res.send('Home Page')
})

app.get('/users', (req, res) => {
  res.send('Users Page!')
})

app.get('/my-profile',
  jwtExpress({
    secret: certPublic,
    algorithms: ['RS256'],
    requestProperty: 'auth',
  }),
  customCORSAndAuthErrorMiddleware,
  (req, res, next) => {
    if (!req.auth) {
      return res.sendStatus(403);
    }
    next()
  }, 
  (req, res) => {
  res.send(`Users Page! ${JSON.stringify(req.auth)}`);
})

app.get('/public', (req, res) => {
  res.type('text/plain');
  res.send(certPublic)
})

app.get('/sign/:id', (req, res) => {
  res.type('text/plain');
  const result = jwt.sign({
    userId: req.params.id,
  }, certPrivate, { algorithm: 'RS256'});
  res.send(result)
})

app.use((req, res, next) => {
  next(new Error(errorDescriptor(ERROR_PAGE_NOT_FOUND)));
});

app.use((error, req, res, next) => {
  let errorOut = {};
  let parsed = {};
  try {
    parsed = JSON.parse(error.message);
    errorOut = {
      ...parsed,
    };
  } catch (e) {
    console.log('[API - ERROR] Unknown error, unable to parse the error key, code and message:'.bgYellow.black);
    console.error(error);
    errorOut.code = 500;
    errorOut.key = 'INTERNAL_SERVER_ERROR';
    errorOut.message = error.message;
  }

  res.setHeader('Content-Type', 'application/json');
  res.status(errorOut.code).send(pretty({
    error: 1,
    errors: [
      { ...errorOut },
    ],
    data: null,
  }));
});


const port = process.env.PORT;

app.listen(port, () => {
  console.log(`🚀  Server ready at ${port}`);
})
