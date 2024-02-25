const express = require('express');
const server = express();
const mongoose = require('mongoose');
const cors = require('cors');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const cookieParser = require('cookie-parser');
const { createProduct } = require('./controller/Product');
const productsRouter = require('./routes/Products');
const categoriesRouter = require('./routes/Categories');
const brandsRouter = require('./routes/Brands');
const usersRouter = require('./routes/Users');
const authRouter = require('./routes/Auth');
const cartRouter = require('./routes/Cart');
const ordersRouter = require('./routes/Order');
const { User } = require('./model/User');
const path = require("path")
require("dotenv").config()
const { isAuth, sanitizeUser, cookieExtractor } = require('./services/common');
const { getServers } = require('dns');

const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY)

// const SECRET_KEY = 'SECRET_KEY';
// JWT options


// Webhook ---------------
// This is your Stripe CLI webhook secret for testing your endpoint locally.
const endpointSecret = process.env.WEBHOOK_SECRET;

server.post('/webhook', express.raw({ type: 'application/json' }), (request, response) => {
  const sig = request.headers['stripe-signature'];

  let event;

  try {
    event = stripe.webhooks.constructEvent(request.body, sig, endpointSecret);
  } catch (err) {
    response.status(400).send(`Webhook Error: ${err.message}`);
    return;
  }

  // Handle the event
  switch (event.type) {
    case 'payment_intent.succeeded':
      const paymentIntentSucceeded = event.data.object;
      // Then define and call a function to handle the event payment_intent.succeeded
      break;
    // ... handle other event types
    default:
      console.log(`Unhandled event type ${event.type}`);
  }

  // Return a 200 response to acknowledge receipt of the event
  response.send();
});

const opts = {};
opts.jwtFromRequest = cookieExtractor;
opts.secretOrKey = process.env.JWT_SECRET_KEY; // TODO: should not be in code;

//middlewares

server.use(express.static(path.resolve(__dirname, 'build')))
server.use(cookieParser());
server.use(
  session({
    secret: process.env.SESSION_SECRET_KEY,
    resave: false, // don't save session if unmodified
    saveUninitialized: false, // don't create session until something stored
  })
);

server.use(passport.initialize());
server.use(passport.session());
// server.use(passport.authenticate('session'));
server.use(
  cors({
    exposedHeaders: ['X-Total-Count'],
  })
);

server.use(express.json()); // to parse req.body
server.use('/products', isAuth(), productsRouter.router);
// we can also use JWT token for client-only auth
server.use('/categories', isAuth(), categoriesRouter.router);
server.use('/brands', isAuth(), brandsRouter.router);
server.use('/users', isAuth(), usersRouter.router);
server.use('/auth', authRouter.router);
server.use('/cart', isAuth(), cartRouter.router);
server.use('/orders', isAuth(), ordersRouter.router);
// If above path doesn't match----------
server.get("*", (req, res) => { res.sendFile(path.resolve("build", "index.html")) })

// Passport Strategies
passport.use(
  'local',
  new LocalStrategy(
    { usernameField: 'email' },
    async function (email, password, done) {
      // by default passport uses username
      try {
        const user = await User.findOne({ email: email });
        if (!user) {
          return done(null, false, { message: 'invalid credentials' }); // for safety
        }
        crypto.pbkdf2(
          password,
          user.salt,
          310000,
          32,
          'sha256',
          async function (err, hashedPassword) {
            if (!crypto.timingSafeEqual(user.password, hashedPassword)) {
              return done(null, false, { message: 'invalid credentials' });
            }
            const token = jwt.sign(sanitizeUser(user), process.env.JWT_SECRET_KEY);
            console.log("token", token)
            done(null, { id: user.id, role: user.role, token: token }); // this lines sends to serializer
          }
        );
      } catch (err) {
        done(err);
      }
    })
);

passport.use(
  'jwt',
  new JwtStrategy(opts, async function (jwt_payload, cb) {
    try {
      const user = await User.findById(jwt_payload.id);
      console.log("jwt data", { jwt_payload });
      if (user) {
        return cb(null, sanitizeUser(user)); // this calls serializer
      } else {
        return cb(null, false);
      }
    } catch (err) {
      return cb(err, false);
    }
  })
);

// this creates session variable req.user on being called from callbacks
passport.serializeUser(function (user, cb) {
  console.log('serialize', user);
  process.nextTick(function () {
    console.log('next tick')
    return cb(null, { id: user.id, role: user.role });
  });
});

// this changes session variable req.user when called from authorized request

passport.deserializeUser(function (user, cb) {
  console.log('de-serialize', user);
  process.nextTick(function () {
    return cb(null, user);
  });
});

// payment............

// const calculateOrderAmount = (items) => {
//   // Replace this constant with a calculation of the order's amount
//   // Calculate the order total on the server to prevent
//   // people from directly manipulating the amount on the client
//   return 1400;
// };

server.post("/create-payment-intent", async (req, res) => {
  const { totalAmount, orderId } = req.body;
  console.log('payment items', totalAmount)

  // Create a PaymentIntent with the order amount and currency
  const paymentIntent = await stripe.paymentIntents.create({
    amount: totalAmount * 100,
    currency: "usd",
    description: 'Your transaction description here',
    shipping: {
      name: 'Customer Name',
      address: {
        line1: 'Address Line 1',
        line2: 'Address Line 2',
        city: 'City',
        state: 'State',
        postal_code: 'Postal Code',
        country: 'US',
      },
    },
    metadata: {
      orderId
    },
    payment_method: "pm_card_visa",
    // In the latest version of the API, specifying the `automatic_payment_methods` parameter is optional because Stripe enables its functionality by default.
    automatic_payment_methods: {
      enabled: true,
    },
  });

  res.send({
    clientSecret: paymentIntent.client_secret,
  });
});





main().catch((err) => console.log(err));

async function main() {
  await mongoose.connect(process.env.DB_URL);
  console.log('database connected');
}

server.listen(8080, () => {
  console.log('server started');
});
