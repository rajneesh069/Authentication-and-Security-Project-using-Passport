//Requiring modules
const User = require("./model");
require("dotenv").config();
const express = require("express");
const app = express();
const bodyParser = require("body-parser");
const passport = require("passport");
const session = require("express-session");
const GoogleStrategy = require("passport-google-oauth20");

//Middleware Setup
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: true,
}));
app.use(passport.initialize());
app.use(passport.session());
passport.use(User.createStrategy());
passport.serializeUser((user, cb) => {
    process.nextTick(() => {
        cb(null, { id: user.id, username: user.username });
    });
});
passport.deserializeUser((user, cb) => {
    process.nextTick(() => {
        return cb(null, user);
    })
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
},
    (accessToken, refreshToken, profile, cb) => {
        User.findOrCreate({ googleId: profile.id }, (err, user) => {
            return cb(err, user);
        });
    })
);

//Setting up routes

//GET requests
app.get("/auth/google", passport.authenticate("google", { scope: ["profile"] }));

app.get("/auth/google/secrets", passport.authenticate("google", { failureRedirect: "/login" }), (req, res) => {
    res.redirect("/secrets");
});

app.get("/", (req, res) => {
    if (req.isAuthenticated()) {
        res.redirect("/secrets");
    } else {
        res.render("home");
    };
});

app.get("/secrets", (req, res) => {
    if (req.isAuthenticated()) {
        User.findOne({
            $or: [{ googleId: req.user.googleId }, { username: req.user.username }]
        })
            .then((user) => {
                console.log(user);
                const data = {
                    secrets: user.secrets,
                }
                res.render("secrets", data);
            })
            .catch((error) => {
                console.error("Error finding the user", error);
            });
    } else {
        res.redirect("/");
    };
});

app.get("/register", (req, res) => {
    res.render("register");
});

app.get("/login", (req, res) => {
    res.render("login");
});

app.get("/logout", (req, res) => {
    req.logout(() => {
        res.redirect("/");
    });
});

app.get("/submit", (req, res) => {
    if (req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.redirect("/login");
    }
});

//POST requests
app.post("/register", (req, res) => {
    User.register({ username: req.body.username }, req.body.password)
        .then((user) => {
            passport.authenticate("local")(req, res, (err) => {
                if (err) {
                    throw new Error("Error authenticating the user:", err);
                } else {
                    console.log("User authenticated successfully!");
                    res.redirect("/secrets");
                }
            });
        })
        .catch((error) => {
            console.error("Error registering the user:", error);
        });
});


app.post("/login", passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
}));

app.post("/submit", (req, res) => {
    User.findOne({
        $or: [{ googleId: req.user.googleId }, { username: req.user.username }]
    })
        .then((user) => {
            user.secrets.push(req.body.secret);
            user.save()
                .then((savedUser) => {
                    console.log("Successfully saved the secret.", savedUser);
                    res.redirect("/secrets");
                })
                .catch((error) => {
                    console.log("Error saving the secret:", error);
                });
        })
        .catch((error) => {
            console.error("Error finding the user");
        });
});

app.post("/deleteSecret", (req, res) => {
    User.findOne({ _id: req.user.id })
        .then((user) => {
            user.secrets.splice(req.body.index, 1);
            user.save()
                .then((savedUser) => {
                    console.log("Secret Deleted Successfully!", savedUser);
                    res.redirect("/secrets");
                })
                .catch((error) => {
                    console.error("Error deleting the secret", error);
                });
        })
        .catch((error) => {
            console.error("Error finding the user:", error);
        });
})

//PORT Listening
app.listen(3000, () => {
    console.log("Server is up and running!");
})