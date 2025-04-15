const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs'); // ❌ wrong

const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');
// Initialize express app
const app = express();
app.use(cors());
// Middleware
app.use(bodyParser.json());

// Connect to MongoDB
mongoose.connect('mongodb+srv://vgugan16:gugan2004@cluster0.qyh1fuo.mongodb.net/golang?retryWrites=true&w=majority&appName=Cluster0', { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('Connected to MongoDB'))
    .catch((error) => console.error('MongoDB connection error:', error));

    
    const userSchema = new mongoose.Schema({
        username: String,
        password: String,
        balance: { type: Number, default: 0 },
        socialContent: String,
        transactionHistory: [
            {
                type: { type: String }, // 'sent' or 'received'
                to: String,
                from: String,
                amount: Number,
                timestamp: { type: Date, default: Date.now }
            }
        ]
    });
    

module.exports = mongoose.model("User", userSchema);

    
    // Create User model
    const User = mongoose.model('User', userSchema);
    
    // Handle user signup
    app.post('/signup', async (req, res) => {
        const { username, password } = req.body;
    
        try {
            // Check if user already exists
            const existingUser = await User.findOne({ username });
    
            if (existingUser) {
                return res.status(400).json({ success: false, message: 'Username already taken' });
            }
    
            // Hash the password before saving it
            const hashedPassword = await bcrypt.hash(password, 10);
    
            // Create new user
            const newUser = new User({ username, password: hashedPassword });
    
            // Save the user to the database
            await newUser.save();
    
            res.status(201).json({ success: true, message: 'User created successfully' });
        } catch (error) {
            res.status(500).json({ success: false, message: 'Server error', error });
        }
    });
    // POST /add-amount

    // Handle user login
    app.post('/login', async (req, res) => {
        const { username, password } = req.body;
    
        try {
            // Find user in the database
            const user = await User.findOne({ username });
    
            if (!user) {
                return res.status(400).json({ success: false, message: 'User not found' });
            }
    
            // Check if password is correct
            const isMatch = await bcrypt.compare(password, user.password);
    
            if (!isMatch) {
                return res.status(400).json({ success: false, message: 'Invalid credentials' });
            }
    
            // Generate JWT token for successful login
            const token = jwt.sign({ userId: user._id }, 'secretkey', { expiresIn: '1h' });
            console.log(token);
            res.json({ success: true, message: 'Login successful', token });
        } catch (error) {
            res.status(500).json({ success: false, message: 'Server error', error });
        }
    });
   

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
    const token = req.header('Authorization') && req.header('Authorization').split(' ')[1]; // Extract token from Authorization header

    if (!token) {
        return res.status(403).json({ success: false, message: 'Access denied. No token provided.' });
    }

    try {
        const decoded = jwt.verify(token, 'secretkey'); // Verify token with secret key
        req.user = decoded; // Store decoded info (userId) in request object
        next();
    } catch (err) {
        return res.status(401).json({ success: false, message: 'Invalid token.' });
    }
};

// Example of using the middleware in a route
app.get('/dashboard', verifyToken, (req, res) => {
    res.json({ success: true, message: 'Welcome to the dashboard!' });
});
app.get('/user-info', verifyToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId);
        res.json({
            success: true,
            username: user.username,
            email: user.email,
            balance: user.balance,
            transactionHistory: user.transactionHistory
        });
    } catch (err) {
        res.status(500).json({ success: false, message: "Error fetching user info." });
    }
});



app.post('/add-amount', verifyToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId);
        if (!user) {
            return res.status(404).json({ success: false, message: "User not found" });
        }

        const amount = parseFloat(req.body.amount);
        if (isNaN(amount) || amount <= 0) {
            return res.status(400).json({ success: false, message: "Invalid amount." });
        }

        user.balance += amount;
        await user.save();

        res.json({ success: true, message: "Amount added successfully", newBalance: user.balance });
    } catch (error) {
        console.error('Error saving amount:', error);
        res.status(500).json({ success: false, message: "Server error" });
    }
});
app.get('/all-users', async (req, res) => {
    try {
        const users = await User.find({}, 'username email balance socialContent');
        res.json({ success: true, users });
    } catch (error) {
        console.error("Error fetching users:", error);
        res.status(500).json({ success: false, message: "Server error." });
    }
});
app.post('/send-money', verifyToken, async (req, res) => {
    const { recipientUsername, amount } = req.body;
    const senderId = req.user.userId;

    if (!recipientUsername || !amount || amount <= 0) {
        return res.status(400).json({ success: false, message: "Invalid input." });
    }

    try {
        const sender = await User.findById(senderId);
        const recipient = await User.findOne({ username: recipientUsername });

        if (!recipient) {
            return res.status(404).json({ success: false, message: "Recipient not found." });
        }

        if (sender.balance < amount) {
            return res.status(400).json({ success: false, message: "Insufficient balance." });
        }

        // Update balances
        sender.balance -= amount;
        recipient.balance += amount;

        // Save transaction history
        sender.transactionHistory.push({
            type: "sent",
            to: recipient.username,
            amount,
            timestamp: new Date()
        });

        recipient.transactionHistory.push({
            type: "received",
            from: sender.username,
            amount,
            timestamp: new Date()
        });

        await sender.save();
        await recipient.save();

        res.json({ success: true, message: `₹${amount} sent to ${recipient.username}` });

    } catch (err) {
        console.error("Transaction error:", err);
        res.status(500).json({ success: false, message: "Server error." });
    }
});
app.get('/user/:username', verifyToken, async (req, res) => {
  const username = req.params.username;
  const user = await User.findOne({ username }, '-_id username email balance socialContent');

  if (!user) return res.status(404).json({ success: false, message: 'User not found' });

  res.json({ success: true, user });
});

    // Start the server
    const PORT = process.env.PORT || 5000;
    app.listen(PORT, () => console.log(`Server is running on port ${PORT}`));
    
