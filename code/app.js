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
const db = "mongodb://127.0.0.1:27017/FlowLearn"
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
        res.cookie('token', token, { httpOnly: true }).redirect('/dashboard');
    } catch (err) {
        req.flash('error', 'Registration failed. Please try again.');
        res.redirect('/auth?error=Registration failed');
        console.log(err)
    }
});

app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email: email });
        if (!user) {
            req.flash('error', 'Invalid username or Invalid password');
            return res.redirect('/auth?error=Invalid username or Invalid password');
        }

        const validPass = await bcrypt.compare(password, user.password);
        if (!validPass) {
            req.flash('error', 'Invalid username or Invalid password');
            return res.redirect('/auth?error=Invalid username or Invalid password');
        }

        const token = generateToken(user);
        req.flash('success', 'Login successful!');
        res.cookie('token', token, { httpOnly: true }).redirect('/dashboard');
    } catch (err) {
        res.redirect('/auth?error=auth failed');
        console.log(err);
    }
});



const ethUtil = require('ethereumjs-util');
const sigUtil = require('@metamask/eth-sig-util');

// Temporary nonce store
const nonces = {};

// 1. Send a message to sign
app.post('/auth/message', (req, res) => {
    const { address } = req.body;
    if (!address) return res.status(400).send('Wallet address missing');

    const nonce = `Sign this message to login: ${Math.floor(Math.random() * 1000000)}`;
    nonces[address] = nonce;
    res.json({ message: nonce });
});

// 2. Verify signed message
app.post('/auth/verify', async (req, res) => {
    const { address, signature } = req.body;
    const originalMessage = nonces[address];

    if (!originalMessage) return res.status(400).send('No message to verify');

    const msgBufferHex = ethUtil.bufferToHex(Buffer.from(originalMessage, 'utf8'));
    const recoveredAddress = sigUtil.recoverPersonalSignature({
        data: msgBufferHex,
        signature: signature,
    });

    if (recoveredAddress.toLowerCase() === address.toLowerCase()) {
        let user = await User.findOne({ walletAddress: address });

        if (!user) {
            user = new User({
                username: address,
                email: address + '@walletuser.com',
                password: bcrypt.hashSync('dummy-password', 10),
                walletAddress: address
            });
            await user.save();
        }

        const token = generateToken(user);
        res.cookie('token', token, { httpOnly: true }).status(200).send('Logged in');
    } else {
        return res.status(401).send('Invalid signature');
    }
});




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
    console.log(`Study Planner app listening at http://localhost:${port}`);
});
