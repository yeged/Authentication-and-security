//jshint esversion:6

require("dotenv").config();
const express = require("express");
const ejs = require("ejs");
const mongoose = require("mongoose");
const bodyparser = require("body-parser");
const passport = require("passport");
const session = require("express-session");
const passportLocalMongoose = require("passport-local-mongoose");

const app = express();

app.set("view engine", "ejs");
app.use(bodyparser.urlencoded({extended: true}));
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
mongoose.connect(url, {useNewUrlParser: true, useUnifiedTopology: true});
mongoose.set('useCreateIndex', true);

const userSchema = new mongoose.Schema({
  email: String,
  password: String
});

userSchema.plugin(passportLocalMongoose); // hash and salt our pass.

const User = new mongoose.model("User", userSchema);

// CHANGE: USE "createStrategy" INSTEAD OF "authenticate"
passport.use(User.createStrategy());

passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

//DATABASE mongoose

app.get("/", function(req, res){
  res.render("home");
});

app.get("/login", function(req, res){
  res.render("login");
});

app.get("/register", function(req, res){
  res.render("register");
});

app.get("/secrets", function(req, res){

  if(req.isAuthenticated()){
    res.render("secrets");
  }else{
    res.redirect("/login");
  }
});

app.get("/logout", function(req, res){
  req.logout();
  res.redirect("/");
});

app.post("/register", function(req, res){

  User.register({username: req.body.username}, req.body.password, function(err, user){
    if(!err){
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      });
    }else{
      console.log(err);
      res.redirect("/register");
    }
  });
});


app.post("/login", function(req, res){

  const user = new User({
    username: req.body.username,
    password: req.body.password
  });
  req.login(user, function(err){
    if(!err){
      passport.authenticate("local")(req, res, function(){
      res.redirect("/secrets");
      });
    }else{
      console.log(err);
      res.redirect("/");
    }
  });
});






app.listen(3000, function(){
  console.log("Server is running on port 3000");
});
