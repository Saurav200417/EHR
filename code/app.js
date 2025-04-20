const { error } = require('console');
const express = require('express');
const path = require('path');
const app = express();
const bcrypt = require('bcrypt');
const bodyParser = require("body-parser")
const mongoose = require("mongoose");
const User = require("./models/User")
const jwt = require('jsonwebtoken');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const flash = require('connect-flash');
const db = "mongodb://127.0.0.1:27017/EHR"
const port = process.env.PORT || 3000;

// mongoose connection
mongoose.connect(db)
    .then(() => {
        console.log('mongo Connection is successful');
    })
    .catch((err) => {
        console.error('Error connecting to MongoDB:', err);
    });


// Set up EJS as the view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Explicitly define paths for static files
// This ensures CSS, JS, and images are properly served
app.use('/css', express.static(path.join(__dirname, 'public/css')));
app.use('/js', express.static(path.join(__dirname, 'public/js')));
app.use('/img', express.static(path.join(__dirname, 'public/img')));
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(session({
    secret: 'yourSecretKey',
    resave: false,
    saveUninitialized: false
}));

app.use(flash());



// Add this middleware to make flash messages available in all views
app.use((req, res, next) => {
    res.locals.success = req.flash('success');
    res.locals.error = req.flash('error');
    next();
});

// Authentication middleware
const generateToken = (user) => {
    return jwt.sign({ id: user._id }, 'your-secret-key', { expiresIn: '1h' });
};

const verifyToken = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) return res.redirect('/auth');

    jwt.verify(token, 'your-secret-key', (err, decoded) => {
        if (err) return res.redirect('/auth');
        req.user = decoded;
        next();
    });
};

// Routes
app.get('/', (req, res) => {
    res.render('index');
});

// Additional routes
app.get('/about', (req, res) => {
    res.send('about');
});

app.get('/features', (req, res) => {
    res.send('features');
});

app.get('/Home', (req, res) => {
    res.send('index');
});
app.get("/auth", (req, res) => {
    res.render("authPage")
});

// app.get('/dashboard', verifyToken, async (req, res) => {
//     try {
//         // Fetch the logged-in user from the database
//         const user = await User.findById(req.user.id);

//         if (!user) {
//             return res.redirect('/auth'); // Redirect if user not found
//         }

//         // Pass the username to the EJS template
//         res.render("dashboard", { username: user.username });
//     } catch (err) {
//         console.error("Error fetching user:", err);
//         res.redirect('/auth');
//     }
// });
app.get('/dashboard', verifyToken, async (req, res) => {
    try {
        // Fetch the logged-in user from the database
        const user = await User.findById(req.user.id);

        if (!user) {
            return res.redirect('/auth'); // Redirect if user not found
        }

        // Determine if the user is an admin
        const isAdmin = user.role === 'admin'; // Assuming 'role' exists in your User schema

        // Pass username and isAdmin to the EJS template
        res.render("dashboard", {
            username: user.username,
            isAdmin: isAdmin
        });
    } catch (err) {
        console.error("Error fetching user:", err);
        res.redirect('/auth');
    }
});



app.post('/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;

        // Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            req.flash('error', 'Email already registered');
            return res.redirect('/auth');
        }

        console.log(username, email, password)
        const user = new User({
            username: username,
            email: email,
            password: password // Schema will auto-hash
        });
        console.log(user)
        // Save the user to the database
        await user.save();

        // Generate JWT token
        const token = generateToken(user);

        req.flash('success', 'Registration successful!');
        // Set the token as a cookie and redirect
        res.cookie('token', token, { httpOnly: true }).redirect('/admin');
    } catch (err) {
        req.flash('error', 'Registration failed. Please try again.');
        res.redirect('/auth?error=Registration failed');
        console.log(err)
    }
});
// const express = require('express');
// const jwt = require('jsonwebtoken');
// const app = express();

// Example users array
const users = [
    { id: 1, username: 'admin', password: 'admin', role: 'admin' },
    { id: 2, username: 'user', password: 'user', role: 'user' }
];

// Login route - authenticate user and issue token
app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // 1. Verify credentials
        const user = users.find(u => u.username === username && u.password === password);
        if (!user) {
            req.flash('error', 'Invalid username or password');
            return res.redirect('/auth?error=Invalid credentials');
        }

        // 2. Generate JWT token with user ID and role
        const token = jwt.sign(
            {
                sub: user.id,
                role: user.role
            },
            'your_jwt_secret',
            { expiresIn: '24h' }
        );

        // 3. Set token in cookie
        res.cookie('token', token, { httpOnly: true });

        // 4. Redirect based on role
        if (user.role === 'admin') {
            req.flash('success', 'Welcome, Admin!');
            return res.redirect('/admin');
        } else {
            req.flash('success', 'Login successful!');
            return res.redirect('/user');
        }
    } catch (err) {
        console.error('Login error:', err);
        req.flash('error', 'Authentication failed');
        res.redirect('/auth?error=auth failed');
    }
});

// Authentication middleware
const authenticate = (req, res, next) => {
    try {
        // Get token from cookie or Authorization header
        const token = req.cookies?.token ||
            (req.headers['authorization'] && req.headers['authorization'].startsWith('Bearer ')
                ? req.headers['authorization'].substring(7) : null);

        if (!token) {
            req.flash('error', 'Please login to continue');
            return res.redirect('/auth');
        }

        // Verify token
        jwt.verify(token, 'your_jwt_secret', (err, decoded) => {
            if (err) {
                req.flash('error', 'Session expired. Please login again');
                return res.redirect('/auth');
            }

            // Add user data to request
            req.user = decoded;
            next();
        });
    } catch (err) {
        console.error('Authentication error:', err);
        req.flash('error', 'Authentication failed');
        res.redirect('/auth');
    }
};

// Authorization middleware
const authorize = (roles) => (req, res, next) => {
    try {
        if (!req.user) {
            req.flash('error', 'Please login to continue');
            return res.redirect('/auth');
        }

        if (!roles.includes(req.user.role)) {
            req.flash('error', 'Access denied. Insufficient permissions');

            // Redirect to appropriate dashboard based on user's role
            if (req.user.role === 'admin') {
                return res.redirect('/admin');
            } else {
                return res.redirect('/user');
            }
        }

        next();
    } catch (err) {
        console.error('Authorization error:', err);
        req.flash('error', 'Authorization failed');
        res.redirect('/auth');
    }
};

// Admin route - renders admin.ejs template
app.get('/admin', authenticate, authorize(['admin']), (req, res) => {
    // You might want to fetch additional data for the admin dashboard here
    const adminData = {
        title: 'Admin Dashboard',
        user: {
            id: req.user.sub,
            role: req.user.role
        }
        // Add any other data you want to pass to the template
    };

    res.render('admin', adminData);
});

// User route - renders user.ejs template
app.get('/user', authenticate, authorize(['user']), (req, res) => {
    // You might want to fetch specific user data here
    const userData = {
        title: 'User Dashboard',
        user: {
            id: req.user.sub,
            role: req.user.role
        }
        // Add any other data you want to pass to the template
    };

    res.render('user', userData);
});

// // Authentication page route
// app.get('/auth', (req, res) => {
//     res.render('auth', { title: 'Login' });
// });

app.get('/logout', (req, res) => {
    req.flash('error', 'You have been logged out');
    res.clearCookie('token').redirect('/auth');
});

// Simple 404 handler that doesn't depend on a view
app.use((req, res) => {
    res.status(404).send('<h1>404 - Page Not Found</h1><p>The page you requested does not exist.</p><a href="/">Go Home</a>');
});

// Start the server
app.listen(port, () => {
    console.log(`listening at http://localhost:${port}`);
});
