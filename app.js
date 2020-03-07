//jshint esversion:6

require("dotenv").config();
const express = require("express");
const ejs = require("ejs");
const mongoose = require("mongoose");
const bodyparser = require("body-parser");
const passport = require("passport");
const session = require("express-session");
const passportLocalMongoose = require("passport-local-mongoose");
//Google OAuth
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require('mongoose-findorcreate');
const FacebookStrategy = require("passport-facebook");



const app = express();

app.set("view engine", "ejs");
app.use(bodyparser.urlencoded({
  extended: true
}));
app.use(express.static("public"));

// SET UP SESSION
app.use(session({
  secret: "Out little secret.",
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize()); // tell our app use the passport
app.use(passport.session()); // set up our session
// DATABASE mongoose

const url = "mongodb://localhost:27017/userDB";
mongoose.connect(url, {
  useNewUrlParser: true,
  useUnifiedTopology: true
});
mongoose.set('useCreateIndex', true);

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  facebookId: String,
  secrets: [String]
});


userSchema.plugin(passportLocalMongoose); // hash and salt our pass.
userSchema.plugin(findOrCreate);


const User = new mongoose.model("User", userSchema);

// CHANGE: USE "createStrategy" INSTEAD OF "authenticate"
passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({
      googleId: profile.id
    }, function(err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
    clientID: process.env.FB_APP_ID,
    clientSecret: process.env.FB_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets",
    profileFields: ["email"]
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id, email: profile.emails[0].value }, function (err, user) {
      return cb(err, user);
    });
  }
));
//DATABASE mongoose

app.get("/", function(req, res) {
  res.render("home");
});

//Google Strategy
app.get('/auth/google',
  passport.authenticate('google', {
    scope: ['profile']
  }));

app.get('/auth/google/secrets',
  passport.authenticate('google', {
    failureRedirect: '/login'
  }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });
//Google Strategy


// Facebook Strategy
app.get('/auth/facebook',
  passport.authenticate('facebook',{ authType: 'rerequest', scope:['email']}
));

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });
// Facebook Strategy

app.get("/login", function(req, res) {
  res.render("login");
});

app.get("/register", function(req, res) {
  res.render("register");
});

app.get("/secrets", function(req, res) {

  User.find({secrets:{$ne:null}}, function(err, foundUser){
    if(err){
      console.log(err);
    }else{
      res.render("secrets", {secretTexts: foundUser});
    }
  });

});

app.get("/submit", function(req, res) {
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/");
  }
});

app.get("/logout", function(req, res) {
  req.logout();
  res.redirect("/");
});

app.post("/submit", function(req, res) {
  const submittedSecret = req.body.secret;

  User.findById(req.user.id, function(err, foundUser) {
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        foundUser.secrets.push(submittedSecret);
        foundUser.save(function(err) {
          if (err) {
            console.log(err);
          } else {
            res.redirect("/secrets");
          }
        });
      }
    }
  });
});

app.post("/register", function(req, res) {

  User.register({
    username: req.body.username
  }, req.body.password, function(err, user) {
    if (!err) {
      passport.authenticate("local")(req, res, function() {
        res.redirect("/secrets");
      });
    } else {
      console.log(err);
      res.redirect("/register");
    }
  });
});

app.post("/login", function(req, res) {

  const user = new User({
    username: req.body.username,
    password: req.body.password
  });
  req.login(user, function(err) {
    if (!err) {
      passport.authenticate("local")(req, res, function() {
        res.redirect("/secrets");
      });
    } else {
      console.log(err);
      res.redirect("/");
    }
  });
});


app.listen(3000, function() {
  console.log("Server is running on port 3000");
});
