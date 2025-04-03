const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3001;
const SECRET_KEY = process.env.JWT_SECRET || 'your-secret-key'; // Set in .env
const MONGODB_URI = process.env.MONGODB_URI; // Set in .env

app.use(cors());
app.use(express.json());

// MongoDB Connection
mongoose.connect(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true }, // Email for login
  password: { type: String, required: true },
  name: { type: String, required: true },
  age: { type: Number, default: 0 },
  bio: { type: String, default: '' },
  photo: { type: String, default: '' },
  resetToken: String,
  resetTokenExpiry: Date,
});
const User = mongoose.model('User', userSchema);

// Email Setup for Password Reset
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER, // Set in .env
    pass: process.env.EMAIL_PASS, // Set in .env
  },
});

// In-memory data (for demo, will sync with MongoDB where needed)
let likes = []; // { liker: userId, liked: userId }
let messages = {};

// Authentication Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token required' });
  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

// Signup
app.post('/signup', async (req, res) => {
  const { username, password, name, age, bio } = req.body;
  if (!username || !password || !name) {
    return res.status(400).json({ error: 'Username, password, and name are required' });
  }
  try {
    const existingUser = await User.findOne({ username });
    if (existingUser) return res.status(400).json({ error: 'Username already exists' });
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, password: hashedPassword, name, age, bio });
    await user.save();
    const token = jwt.sign({ id: user._id, username: user.username }, SECRET_KEY, { expiresIn: '1h' });
    res.status(201).json({ token, user: { id: user._id, username, name } });
  } catch (err) {
    res.status(500).json({ error: 'Signup failed' });
  }
});

// Login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await User.findOne({ username });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign({ id: user._id, username: user.username }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ token, user: { id: user._id, username, name: user.name } });
  } catch (err) {
    res.status(500).json({ error: 'Login failed' });
  }
});

// Forgot Password
app.post('/forgot-password', async (req, res) => {
  const { username } = req.body;
  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(404).json({ error: 'User not found' });

    const resetToken = jwt.sign({ id: user._id }, SECRET_KEY, { expiresIn: '15m' });
    user.resetToken = resetToken;
    user.resetTokenExpiry = Date.now() + 15 * 60 * 1000; // 15 minutes
    await user.save();

    const resetLink = `http://your-frontend-url/reset-password?token=${resetToken}`; // Update with hosted frontend URL
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: username, // Assuming username is email
      subject: 'Password Reset Request',
      text: `Click this link to reset your password: ${resetLink}. It expires in 15 minutes.`,
    });

    res.json({ message: 'Password reset link sent to your email' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to process request' });
  }
});

// Reset Password
app.post('/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    const user = await User.findOne({ _id: decoded.id, resetToken: token, resetTokenExpiry: { $gt: Date.now() } });
    if (!user) return res.status(400).json({ error: 'Invalid or expired reset token' });

    user.password = await bcrypt.hash(newPassword, 10);
    user.resetToken = null;
    user.resetTokenExpiry = null;
    await user.save();

    res.json({ message: 'Password reset successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Reset failed' });
  }
});

// Get Users (for swiping)
app.get('/users', authenticateToken, async (req, res) => {
  try {
    const users = await User.find({ _id: { $ne: req.user.id } }, 'name age bio photo'); // Exclude current user
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// Post Likes
app.post('/likes', authenticateToken, (req, res) => {
  const { user } = req.body; // user is the liked user's object
  likes.push({ liker: req.user.id, liked: user._id });
  res.status(201).json({ message: 'Liked', user });
});

// Get Matches
app.get('/matches', authenticateToken, async (req, res) => {
  try {
    const yourLikes = likes.filter(l => l.liker === req.user.id).map(l => l.liked);
    const mutualMatches = await User.find({
      _id: { $in: likes.filter(l => l.liked === req.user.id && yourLikes.includes(l.liker)).map(l => l.liker) },
    }, 'name age bio photo');
    res.json(mutualMatches);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch matches' });
  }
});

// Get Messages
app.get('/messages/:userId', authenticateToken, async (req, res) => {
  const { userId } = req.params;
  const chatKey = [req.user.id, userId].sort().join(':');
  res.json(messages[chatKey] || []);
});

// Post Messages
app.post('/messages/:userId', authenticateToken, async (req, res) => {
  const { userId } = req.params;
  const { text } = req.body;
  const chatKey = [req.user.id, userId].sort().join(':');
  if (!messages[chatKey]) messages[chatKey] = [];
  const sender = await User.findById(req.user.id);
  const message = { sender: sender.name, text, timestamp: Date.now() };
  messages[chatKey].push(message);

  // Simulated reply (for demo)
  setTimeout(async () => {
    const recipient = await User.findById(userId);
    messages[chatKey].push({
      sender: recipient.name,
      text: `Hey! ${text}`,
      timestamp: Date.now(),
    });
  }, 1000);

  res.status(201).json(message);
});

// Profile (Get and Update)
app.get('/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id, 'name age bio photo');
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

app.post('/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    user.name = req.body.name || user.name;
    user.age = req.body.age || user.age;
    user.bio = req.body.bio || user.bio;
    user.photo = req.body.photo || user.photo;
    await user.save();
    res.json({ name: user.name, age: user.age, bio: user.bio, photo: user.photo });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});