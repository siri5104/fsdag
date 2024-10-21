// server.js

const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const cors = require('cors');
const mongoose = require('mongoose');
const fs = require('fs');
const { promises: fsPromises } = require('fs');
require('dotenv').config();

const passport = require('passport');
const session = require('express-session');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.static('public'));

// Session middleware (required for Passport)
app.use(session({
    secret: 'ssstkp991011323', // Replace with a secure secret key
    resave: false,
    saveUninitialized: true,
}));

// Initialize Passport middleware
app.use(passport.initialize());
app.use(passport.session());

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/eventMang', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.then(() => console.log('Connected to MongoDB'))
.catch(err => {
    console.error('MongoDB connection error:', err);
    process.exit(1);
});

// User Schema
const userSchema = new mongoose.Schema({
    name: String,
    email: { type: String, required: true, unique: true },
    password: String, // Password is optional for social login users
    googleId: String, // For storing Google ID
});

const User = mongoose.model('User', userSchema);

// Passport serialization
passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const user = await User.findById(id);
        done(null, user);
    } catch (err) {
        done(err, null);
    }
});

// Configure Google Strategy
passport.use(new GoogleStrategy({
    clientID: '449362220716-gfk5rd5401f7grkmqb6br5n91p2parlt.apps.googleusercontent.com', // Replace with your Google Client ID
    clientSecret: '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', // Replace with your Google Client Secret
    callbackURL: 'http://localhost:3000/auth/google/callback',
}, async (accessToken, refreshToken, profile, done) => {
    try {
        let user = await User.findOne({ googleId: profile.id });
        if (user) {
            return done(null, user); // User exists, proceed
        } else {
            // Create a new user
            user = new User({
                name: profile.displayName,
                email: profile.emails[0].value,
                googleId: profile.id,
            });
            await user.save();
            return done(null, user); // New user created
        }
    } catch (err) {
        return done(err, null);
    }
}));

// Routes for Google OAuth
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback',
    passport.authenticate('google', {
        failureRedirect: '/login1.html',
    }),
    (req, res) => {
        // Successful authentication
        res.redirect('/profile.html'); // Redirect to profile page
    }
);

// API route to get user data
app.get('/api/user', (req, res) => {
    if (req.isAuthenticated()) {
        // If user is authenticated, send their name
        return res.json({ name: req.user.name });
    } else {
        // If not authenticated, send a fallback
        return res.json({ name: 'Guest' });
    }
});

// Logout route
app.get('/logout', (req, res) => {
    req.logout();
    res.redirect('/index.html'); // Redirect to main page after logout
});

// Sign Up Route
app.post('/signup', async (req, res) => {
    try {
        const { name, email, password, confirmPassword } = req.body;

        // Validation
        if (!name || !email || !password || !confirmPassword) {
            return res.status(400).json({
                success: false,
                error: 'All fields are required',
            });
        }

        if (password !== confirmPassword) {
            return res.status(400).json({
                success: false,
                error: 'Passwords do not match',
            });
        }

        // Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({
                success: false,
                error: 'Email already registered',
            });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create a new user in MongoDB
        const user = new User({
            name,
            email,
            password: hashedPassword,
        });
        await user.save();

        // Read the current contents of data.json
        let users = [];
        if (fs.existsSync('data.json')) {
            const data = await fsPromises.readFile('data.json', 'utf-8');
            users = JSON.parse(data);
        }

        // Add the new user (excluding password for security)
        users.push({
            name,
            email,
        });

        // Write the updated users array to data.json
        await fsPromises.writeFile('data.json', JSON.stringify(users, null, 2), 'utf-8');

        res.status(201).json({
            success: true,
            message: 'Registration successful',
        });
    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({
            success: false,
            error: 'Internal server error',
        });
    }
});

// Login Route
app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Validation
        if (!email || !password) {
            return res.status(400).json({
                success: false,
                error: 'Email and password are required',
            });
        }

        // Find the user by email
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({
                success: false,
                error: 'Invalid credentials',
            });
        }

        // Compare password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({
                success: false,
                error: 'Invalid credentials',
            });
        }

        res.json({
            success: true,
            name: user.name,
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            success: false,
            error: 'Internal server error',
        });
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({
        success: false,
        error: 'Internal server error',
    });
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
