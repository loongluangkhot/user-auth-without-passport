// REQUIRE DEPENDENCIES
const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const sessions = require('client-sessions');
const bcrypt = require('bcryptjs');
const csurf = require('csurf');
const User = require('./models/user');


// SET UP APP
const app = express();
app.set('view engine', 'pug');
app.use(bodyParser.urlencoded({extended: true}));


// SET UP SESSIONS AND COOKIES
app.use(sessions({
  cookieName: 'session', // cookie name dictates the key name added to the request object
  secret: 'flymetothemoon', // should be a large unguessable string
  duration: 30 * 60 * 1000, // how long the session will stay valid in ms
  cookie: {
    ephemeral: true, // when true, cookie expires when the browser closes
    httpOnly: true, // when true, cookie is not accessible from javascript
    secure: false // when true, cookie will only be sent over SSL. use key 'secureProxy' instead if you handle SSL not in your node process
  }
}));


// MIDDLEWARE TO HELP APP IDENTIFY USER IN THE SESSION
app.use(function(req, res, next) {
  if(!(req.session && req.session.userId)) {
      return next();
  } 
  User.findById(req.session.userId, function(err, foundUser) {
      if(err) {
          return next(err);
      } 
      if(!foundUser) {
          return next();
      }
      
      foundUser.password = undefined;
      req.user = foundUser;
      res.locals.user = foundUser;
      
      next();
  });
});


// SET UP DB
mongoose.connect('mongodb://localhost:27017/user_auth_no_passport', { useNewUrlParser: true });

// ==================================
// ROUTING
//===================================

// INDEX
app.get('/', function(req, res) {
    res.render('index', {title: 'Home'});
});

// REGISTER
app.get('/register', function(req, res) {
    res.render('register', {title: 'Register', csrfToken: req.csrfToken()}); 
});

app.post('/register', function(req, res) {
    let hash = bcrypt.hashSync(req.body.user.password, 14);
    req.body.user.password = hash;
    User.create(req.body.user, function(err, createdUser) {
       if(err) {
           console.log(err);
           res.send('Something went wrong! Please try again!');
       } else {
           console.log(createdUser);
           req.session.userId = createdUser._id;
           res.redirect('/secret');
       }
    });
});

// LOGIN
app.get('/login', function(req, res) {
    if(req.user) {
        res.redirect('/secret');
    } else {
        res.render('login', {title: 'Log In'});
    }
});

app.post('/login', function(req, res) {
    User.findOne({username: req.body.user.username}, function(err, foundUser) {
        if(err) {
            console.log(err);
            console.log('Something went wrong! Please try again!');
        } else if(!foundUser || !bcrypt.compareSync(req.body.user.password, foundUser.password)) {
            res.send('Wrong username / password');
        } else {
            req.session.userId = foundUser._id;
            res.redirect('/secret');
        }
    });
});

// LOGOUT
app.get('/logout', function (req, res) {
    if(!req.session) {
        res.send(`Sorry! You've not logged in!`);
    } else {
        req.session.reset();
        res.redirect('/');
    }
});

app.get('/secret', loginRequired, function(req, res) {
    res.render('secret', {title: 'Secret', csrfToken: req.csrfToken()}); 
});


// MIDDLEWARE
function loginRequired(req, res, next) {
    if(!req.user) {
        res.send(`Sorry! You've not logged in!`);
    }
    next();
}


// START SERVER
app.listen(process.env.PORT, process.env.IP, function() {
    console.log('Server started...');
})