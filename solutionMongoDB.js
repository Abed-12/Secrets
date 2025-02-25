import express from "express";
import bodyParser from "body-parser";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import env from "dotenv";

const app = express();
const saltRounds = 10; // Number of rounds of (salting rounds) hashing
env.config();
const port = process.env.PORT;

mongoose.connect(process.env.MONGO_CONN);
console.log("Connected to MongoDB successfully");

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    secret: String // Add a secret field to store the secret
});

const User = mongoose.model('User', userSchema);

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

// create new session to save user login sessions
app.use(
    session({
        secret: process.env.SESSION_SECRET,
        resave: false,
        saveUninitialized: true,
        cookie: {
            maxAge: 1000 * 60 * 60 * 24
        }
    })
);

// initialize passport
app.use(passport.initialize());
app.use(passport.session());

app.get("/", (req, res) => {
    res.render("home.ejs");
});

app.get("/login", (req, res) => {
    res.render("login.ejs");
});

app.get("/register", (req, res) => {
    res.render("register.ejs");
});


app.get("/secrets", async (req, res) => {
    console.log(req.user);
    ////////////////UPDATED GET SECRETS ROUTE/////////////////
    //TODO: Update this to pull in the user secret to render in secrets.ejs
    // التأكد من أن المستخدم مصدق (isAuthenticated)
    if (req.isAuthenticated()) {
        try {
            // البحث عن المستخدم بناءً على البريد الإلكتروني باستخدام Mongoose
            const user = await User.findOne({ email: req.user.email });
            // إذا كان لدى المستخدم حقل secret
            const secret = user.secret;
            if (secret) {
                res.render("secrets.ejs", { secret: secret });
            } else {
                // إذا لم يكن لدى المستخدم secret، عرض رسالة افتراضية
                res.render("secrets.ejs", { secret: "Jack Bauer is my hero." });
            }
        } catch (err) {
            console.log(err);
            res.status(500).send("An error occurred while fetching the secret.");
        }
    } else {
        res.redirect("/login");
    }
});


////////////////SUBMIT GET ROUTE/////////////////
//TODO: Add a get route for the submit button
//Think about how the logic should work with authentication.
app.get("/submit", (req, res) => {
    if (req.isAuthenticated()) {
        res.render("submit.ejs");
    } else {
        res.redirect("/login");
    }
});

app.get(
    "/auth/google",
    passport.authenticate("google", {
        scope: ["profile", "email"],
    })
);

app.get(
    "/auth/google/secrets",
    passport.authenticate("google", {
        successRedirect: "/secrets",
        failureRedirect: "/login",
    })
);

app.get("/logout", (req, res) => {
    req.logout(function (err) {
        if (err) {
            return next(err);
        }
        res.redirect("/");
    });
});

app.post("/login",
    passport.authenticate("local", {
        successRedirect: "/secrets",
        failureRedirect: "/login",
    })
);

app.post("/register", async (req, res) => {
    const email = req.body.username;
    const password = req.body.password;

    try {
        // Check if the user with the email already exists
        const existingUser = await User.findOne({ email: email });
    
        if (existingUser) {
            res.redirect("/login")
        } else {
            //hashing the password and saving it in the database
            bcrypt.hash(password, saltRounds, async (err, hash) => {
                if (err) {
                    console.error("Error hashing password:", err);
                } else {
                    console.log("Hashed Password:", hash);
                    // Create and save the new user
                    const newUser = new User({
                        email: email,
                        password: hash
                    });

                    try {
                        const user = await newUser.save();

                        // Log the user in after successful registration
                        req.login(user, (err) => {
                            if (err) {
                                console.error("Login error:", err);
                                res.status(500).send("Login error");
                            } else {
                                console.log("success");
                                res.redirect("/secrets");
                            }
                        });
                    } catch (err) {
                        console.error("Error saving user:", err);
                        res.status(500).send("Error saving user");
                    }
                }
            });
        }
    } catch (err) {
        console.log(err);
        res.status(500).send("Server error");
    }
});

////////////////SUBMIT POST ROUTE/////////////////
//TODO: Create the post route for submit.
//Handle the submitted data and add it to the database
app.post("/submit", async function (req, res) {
    const submittedSecret = req.body.secret;
    console.log(req.user);

    try {
        // Find & Update user in mongoDB 
        await User.findOneAndUpdate(
            { email: req.user.email }, // البحث عن المستخدم بناءً على البريد الإلكتروني
            { secret: submittedSecret } // تحديث الحقل
        );
        res.redirect("/secrets");
    } catch (err) {
        console.log(err);
        res.status(500).send("An error occurred while updating the secret.");
    }
});

passport.use("local",
    new Strategy(async function verify(username, password, cd){
        try {
            // Find the user by email
            const user = await User.findOne({ email: username });
            
            if (user) {
                const storedHashedPassword = user.password; // Changed name from storedPassword to storedHashedPassword
                // Compare the hashed password with the provided password (verifying the password)
                bcrypt.compare(password, storedHashedPassword, (err, result) => {
                    if (err) {
                        return cd(err);
                    } else {
                        if (result) {
                            return cd(null, user); // put the null because no error here
                        } else {
                            return cd(null, false);
                        }
                    }
                });
            } else {
                return cd("User not found")
            }
        } catch (err) {
            return cd(err);
        }
    })
);

// Strategies for authenticating with Google
passport.use("google",
    new GoogleStrategy(
        {
            clientID: process.env.GOOGLE_CLIENT_ID,
            clientSecret: process.env.GOOGLE_CLIENT_SECRET,
            callbackURL: "http://localhost:3000/auth/google/secrets",
            userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
        },
        async (accessToken, refreshToken, profile, cb) => {
            try {
                console.log(profile); // This is information the user's profile from Google

                // Find user by email in MongoDB
                const user = await User.findOne({ email: profile.email});

                if (!user) {
                    // If user doesn't exist, create a new user
                    const newUser = new User({
                        email: profile.email,
                        password: "google", // Since Google OAuth doesn't return a password
                    });

                    await newUser.save();
                    return cb(null, newUser);
                } else {
                    // User found
                    return cb(null, user);
                }
            } catch (err) {
                return cb(err);
            }
        }
    )
);

// Serialize the user to the session
passport.serializeUser((user, cb) => {
    cb(null, user);
});
// Deserialize the user from the session
passport.deserializeUser((user, cb) => {
    cb(null, user);
});

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});