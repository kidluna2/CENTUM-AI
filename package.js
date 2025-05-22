const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI, {
useNewUrlParser: true,
useUnifiedTopology: true,
});

// User Schema
const userSchema = new mongoose.Schema({
name: String,
email: { type: String, unique: true },
password: String,
role: { type: String, enum: ['annotator', 'admin'], default: 'annotator' },
});

const User = mongoose.model('User', userSchema);

// Signup Route
app.post('/signup', async (req, res) => {
const { name, email, password, role } = req.body;
const hashedPassword = await bcrypt.hash(password, 10);
try {
const user = new User({ name, email, password: hashedPassword, role });
await user.save();
res.status(201).json({ message: 'User created successfully' });
} catch (err) {
res.status(400).json({ error: 'Email already exists' });
}
});

// Login Route
app.post('/login', async (req, res) => {
const { email, password } = req.body;
const user = await User.findOne({ email });
if (!user) return res.status(400).json({ error: 'Invalid credentials' });

const isMatch = await bcrypt.compare(password, user.password);
if (!isMatch) return res.status(400).json({ error: 'Invalid credentials' });

const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, {
expiresIn: '1d',
});
res.json({ token });
});

// Middleware to verify JWT
const authMiddleware = (req, res, next) => {
const token = req.headers.authorization;
if (!token) return res.status(401).json({ error: 'Access denied' });

try {
const verified = jwt.verify(token, process.env.JWT_SECRET);
req.user = verified;
next();
} catch (err) {
res.status(400).json({ error: 'Invalid token' });
}
};

app.listen(5000, () => console.log('Server running on port 5000'));