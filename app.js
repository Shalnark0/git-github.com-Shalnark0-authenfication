require("dotenv").config();

const PORT = process.env.PORT;
const MONGODB_URL = process.env.MONGODB_URL;

const express = require("express");
const path = require("path");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const mongoose = require("mongoose");
const Schema = mongoose.Schema;
const bcrypt = require('bcryptjs');

mongoose.connect(MONGODB_URL);
const db = mongoose.connection;
db.on("error", console.error.bind(console, "mongo connection error"));

const User = mongoose.model(
  "User",
  new Schema({
    username: { type: String, required: true },    
    password: { type: String, required: true } ,
    membership_status: { type: String, required: true }
  })
);

const Message = mongoose.model(
  "Message",
  new Schema({
    title: { type: String, required: true },
    text: { type: String, required: true },
    user: { type: Schema.Types.ObjectId, ref: "User", required: true },
    time_stamp: { type: Date, default: Date.now, required: true }
  })
);

const MembershipStatus = mongoose.model(
  "MembershipStatus",
  new Schema({
    pass: { type: String, required: true },
    name: { type: String, required: true }
  })
);


const app = express();
app.set("views", __dirname);
app.set("view engine", "ejs");

app.use(session({ secret: "cats", resave: false, saveUninitialized: true }));
app.use(passport.session());
app.use(express.urlencoded({ extended: false }));

app.get("/", (req, res) => {
  res.render("index", { user: req.user });
  console.log(req.user)
});

app.get("/log-out", (req, res, next) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
}); 


app.get("/sign-up", (req, res) => res.render("sign-up-form"));

app.post("/sign-up", async (req, res, next) => {
  try {
    bcrypt.hash(req.body.password, 10, async (err, hashedPassword) => {
      if (err) {
        return next(err);
      }
      const user = new User({
        username: req.body.username,        
        password: hashedPassword,
        membership_status: 'default' // Set default membership status
      });
      const result = await user.save();
      res.redirect("/");
    });
  } catch (err) {
    return next(err);
  }
});


// Middleware to check passcode
const checkPasscode = async (req, res, next) => {
  const passcode = req.body['clubmember-validation']; // Assuming passcode is sent via POST request
  
  try {
    // Retrieve the correct passcode from the database
    const membershipStatus = await MembershipStatus.findOne({ name: "clubmember" });
    if (!membershipStatus) {
      // Handle case where membership status document is not found
      console.error("Membership status document not found in database");
      // Optionally, you can provide a default behavior or throw an error
      // throw new Error("Membership status not found");
      req.session.membership_status = 'default'; // Set default membership status
    } else {
      console.log(membershipStatus)
      // Compare passcode with retrieved membershipStatus.pass
      if (passcode === membershipStatus.pass) {
        req.session.membership_status = 'clubmember'; // Store membership status in session
      } else {
        req.session.membership_status = 'default'; // Reset membership status in session if passcode is incorrect
      }
    }
    next();
  } catch (err) {
    next(err);
  }
};

// Route to handle sending a message
app.post("/send-message", checkPasscode, async (req, res, next) => {
  try {
    if (!req.user) {
      return res.redirect("/");
    }
    if (req.session.membership_status === 'clubmember') {
      const message = new Message({
        title: req.body.title,
        text: req.body.message,
        user: req.user._id
      })
    const result = await message.save();
    res.redirect("/messages-for-clubmembers");
    } else{
      // Handle non-clubmember behavior (optional redirect or error message)
      return res.redirect("/messages")
    }
  } catch (err) {
    return next(err);
  }
});

// Route to render messages based on membership status
app.get("/messages", async (req, res, next) => {
  try {
    let messages = [];

    if (req.session.membership_status === 'clubmember') {
      // Fetch messages and populate user details
      messages = await Message.find().populate('user').exec();
      res.render("messages-for-clubmembers", { messages });
    } else {
      // Render simple messages view for non-club members
      messages = await Message.find().exec();
      res.render("messages", { messages });
    }
  } catch (err) {
    next(err);
  }
});

app.post(
  "/log-in",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/"
  })
);



passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const user = await User.findOne({ username: username });
      if (!user) {
        return done(null, false, { message: "Incorrect username" });
      }
      const match = await bcrypt.compare(password, user.password);
      if (!match) {
        return done(null, false, { message: "Incorrect password" });
      }
      return done(null, user);
    } catch (err) {
      return done(err);
    }
  })
);

app.use((req, res, next) => {
  res.locals.currentUser = req.user;
  next();
});

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

app.listen(PORT, () => console.log(`app listening on port ${PORT}!`));