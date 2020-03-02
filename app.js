//jshint esversion:6

require("dotenv").config();
const express = require("express");
const ejs = require("ejs");
const mongoose = require("mongoose");
const bodyparser = require("body-parser");
const encrypt = require("mongoose-encryption");
const md5 = require("md5");

const app = express();

app.set("view engine", "ejs");
app.use(bodyparser.urlencoded({extended: true}));
app.use(express.static("public"));

// DATABASE mongoose

const url = "mongodb://localhost:27017/userDB";
mongoose.connect(url, {useNewUrlParser: true, useUnifiedTopology: true});

const userSchema = new mongoose.Schema({
  email: String,
  password: String
});


//userSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields: ["password"]}); // LEVEL 2 SECURITY.

const User = new mongoose.model("User", userSchema);


console.log(md5("123456"));



app.get("/", function(req, res){
  res.render("home");
});

app.get("/login", function(req, res){
  res.render("login");
});

app.get("/register", function(req, res){
  res.render("register");
});


app.post("/register", function(req, res){
  const newUser = new User({
    email: req.body.username,
    password: md5(req.body.password)
  });
  newUser.save(function(err){
    if(!err){
      res.render("secrets");
    }else{
      console.log(err);
    }
  });
});


app.post("/login", function(req, res){
  const username = req.body.username;
  const password = md5(req.body.password);

  User.findOne({email: username}, function(err, foundUser){
    if(!err){
      if(foundUser){
        if(foundUser.password === password){
          res.render("secrets");
        }else{
          console.log("invalid password");
        }
      }else{
        console.log("invalid email");
      }
    }else{
      console.log(err);
    }
  });
});






app.listen(3000, function(){
  console.log("Server is running on port 3000");
});
