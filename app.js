//Requiring modules
const User = require("./model");
require("dotenv").config();
const express = require("express");
const app = express();
const bodyParser = require("body-parser");
const passport = require("passport");
const session = require("express-session");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const GitHubStrategy = require("passport-github2").Strategy
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

passport.use(new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/github/secrets"
},
    function (accessToken, refreshToken, profile, done) {
        console.log("GitHub Profile", profile.id);
        User.findOrCreate({ githubId: profile.id }, function (err, user) {
            return done(err, user);
        });
    }
));

//Setting up routes

//GET requests
app.get("/auth/google", passport.authenticate("google", { scope: ["profile"] }));

app.get("/auth/google/secrets", passport.authenticate("google", { failureRedirect: "/login" }), (req, res) => {
    res.redirect("/secrets");
});

app.get('/auth/github',
    passport.authenticate("github", { scope: ["profile"] }));

app.get('/auth/github/secrets',
    passport.authenticate('github', { failureRedirect: '/login' }),
    function (req, res) {
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
            $or: [{ googleId: req.user.googleId }, { username: req.user.username }, { githubId: req.user.githubId }]
        })
            .then((user) => {
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

app.get("/failedLogin", (req, res) => {
    res.render("failedLogin");
});

app.get("/failedRegister", (req, res) => {
    res.render("failedRegister");
})

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
            res.redirect("/failedRegister");
            console.error("Error registering the user:", error);
        });
});


app.post("/login", passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/failedLogin",
}));

app.post("/submit", (req, res) => {
    User.findOne({
        $or: [{ googleId: req.user.googleId }, { username: req.user.username }, { githubId: req.user.githubId }]
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