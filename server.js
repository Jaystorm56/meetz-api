const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const http = require('http');
const { Server } = require('socket.io');
const cookieParser = require('cookie-parser');
require('dotenv').config();

const app = express();
const server = http.createServer(app); // Create HTTP server for Socket.IO
const io = new Server(server, {
  cors: {
    origin: 'https://meetz-six.vercel.app', // Adjust this to your frontend URL in production
    methods: ['GET', 'POST'],
    credentials: true,
  },
});

const port = process.env.PORT || 3001;
const ACCESS_TOKEN_SECRET = process.env.JWT_SECRET || 'your-access-secret-key';
const REFRESH_TOKEN_SECRET = process.env.JWT_REFRESH_SECRET || 'your-refresh-secret-key';
const MONGODB_URI = process.env.MONGODB_URI;

app.use(cors({
  origin: 'https://meetz-six.vercel.app', // <-- Set to your deployed frontend URL
  credentials: true,
}));
app.use(express.json());
app.use(cookieParser());

// MongoDB Connection
mongoose.connect(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  age: { type: Number, default: 0 },
  bio: { type: String, default: '' },
  gender: { type: String, default: '' },
  interests: { type: [String], default: [] },
  photos: { type: [String], default: [] },
  resetToken: String,
  resetTokenExpiry: Date,
  likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  refreshToken: { type: String }, // Store refresh token for revocation
});
const User = mongoose.model('User', userSchema);

// Match Schema
const matchSchema = new mongoose.Schema({
  user1Id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  user2Id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  createdAt: { type: Date, default: Date.now },
});
const Match = mongoose.model('Match', matchSchema);

// Message Schema
const messageSchema = new mongoose.Schema({
  chatId: { type: String, required: true }, // e.g., "user1:user2"
  senderId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  text: { type: String, required: true },
  timestamp: { type: Date, default: Date.now },
});
const Message = mongoose.model('Message', messageSchema);

// Email Setup for Password Reset
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Generate Tokens
const generateAccessToken = (user) => {
  return jwt.sign({ id: user._id, username: user.username }, ACCESS_TOKEN_SECRET, { expiresIn: '15m' });
};
const generateRefreshToken = (user) => {
  return jwt.sign({ id: user._id, username: user.username }, REFRESH_TOKEN_SECRET, { expiresIn: '7d' });
};

// Authentication Middleware (from cookie)
const authenticateToken = (req, res, next) => {
  const token = req.cookies['accessToken'];
  if (!token) return res.status(401).json({ error: 'Token required' });
  jwt.verify(token, ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

// Socket.IO Logic
io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  // User joins their own room (based on user ID) for notifications
  socket.on('joinUser', (userId) => {
    socket.join(userId);
    console.log(`User ${userId} joined their room`);
  });

  // User joins a chat room (based on chatId)
  socket.on('joinChat', (chatId) => {
    socket.join(chatId);
    console.log(`User joined chat ${chatId}`);
  });

  // Handle sending a message
  socket.on('sendMessage', async (data) => {
    const { chatId, senderId, recipientId, text } = data;
    try {
      const message = new Message({
        chatId,
        senderId,
        text,
        timestamp: new Date(),
      });
      await message.save();

      // Only emit to the chat room, not to individual users
      io.to(chatId).emit('receiveMessage', {
        chatId,
        senderId,
        recipientId,
        text,
        timestamp: message.timestamp,
      });

      // Send notification only to the recipient
      socket.to(recipientId).emit('newMessageNotification', {
        chatId,
        senderId,
        text,
      });
    } catch (err) {
      console.error('Error saving message:', err);
    }
  });

  socket.on('disconnect', () => {
    console.log('User disconnected:', socket.id);
  });
});

// Signup
app.post('/signup', async (req, res) => {
  const { username, password, firstName, lastName, termsAgreed } = req.body;
  
  // Add request body logging
  console.log('Signup request body:', { username, firstName, lastName, termsAgreed });
  
  if (!username || !password || !firstName || !lastName || !termsAgreed) {
    console.log('Missing required fields');
    return res.status(400).json({ error: 'All fields and terms agreement are required' });
  }
  
  try {
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      console.log('Username already exists:', username);
      return res.status(400).json({ error: 'Username already exists' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, password: hashedPassword, firstName, lastName });
    await user.save();
    
    // Generate tokens
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);
    user.refreshToken = refreshToken;
    await user.save();
    
    // Log cookie setting
    console.log('Setting cookies for user:', username);
    
    // Set cookies with domain
    res.cookie('accessToken', accessToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
      maxAge: 15 * 60 * 1000,
      domain: '.onrender.com'
    });
    
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
      maxAge: 7 * 24 * 60 * 60 * 1000,
      domain: '.onrender.com'
    });
    
    res.status(201).json({ 
      user: { id: user._id, username, firstName, lastName },
      message: 'Signup successful'
    });
    
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ 
      error: 'Signup failed', 
      details: err.message,
      stack: process.env.NODE_ENV === 'development' ? err.stack : undefined
    });
  }
});

// Login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  
  // Add request body logging
  console.log('Login attempt for:', username);
  
  try {
    const user = await User.findOne({ username });
    if (!user) {
      console.log('User not found:', username);
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      console.log('Invalid password for user:', username);
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Generate tokens
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);
    user.refreshToken = refreshToken;
    await user.save();
    
    // Log cookie setting
    console.log('Setting cookies for user:', username);
    
    // Set cookies with domain
    res.cookie('accessToken', accessToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
      maxAge: 15 * 60 * 1000,
      domain: '.onrender.com'
    });
    
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
      maxAge: 7 * 24 * 60 * 60 * 1000,
      domain: '.onrender.com'
    });
    
    res.json({ 
      user: { id: user._id, username, firstName: user.firstName, lastName: user.lastName },
      message: 'Login successful'
    });
    
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ 
      error: 'Login failed',
      details: err.message,
      stack: process.env.NODE_ENV === 'development' ? err.stack : undefined
    });
  }
});

// Refresh Token Endpoint
app.post('/refresh-token', async (req, res) => {
  const refreshToken = req.cookies['refreshToken'];
  if (!refreshToken) return res.status(401).json({ error: 'Refresh token required' });
  try {
    const payload = jwt.verify(refreshToken, REFRESH_TOKEN_SECRET);
    const user = await User.findById(payload.id);
    if (!user || user.refreshToken !== refreshToken) {
      return res.status(403).json({ error: 'Invalid refresh token' });
    }
    // Generate new access token
    const newAccessToken = generateAccessToken(user);
    res.cookie('accessToken', newAccessToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
      maxAge: 15 * 60 * 1000,
    });
    res.json({ success: true });
  } catch (err) {
    res.status(403).json({ error: 'Invalid refresh token' });
  }
});

// Logout
app.post('/logout', authenticateToken, async (req, res) => {
  const user = await User.findById(req.user.id);
  if (user) {
    user.refreshToken = null;
    await user.save();
  }
  res.clearCookie('accessToken', {
    httpOnly: true,
    secure: true,
    sameSite: 'none'
  });
  res.clearCookie('refreshToken', {
    httpOnly: true,
    secure: true,
    sameSite: 'none'
  });
  res.json({ success: true });
});

// Forgot Password
app.post('/forgot-password', async (req, res) => {
  const { username } = req.body;
  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(404).json({ error: 'User not found' });

    const resetToken = jwt.sign({ id: user._id }, ACCESS_TOKEN_SECRET, { expiresIn: '15m' });
    user.resetToken = resetToken;
    user.resetTokenExpiry = Date.now() + 15 * 60 * 1000; // 15 minutes
    await user.save();

    const resetLink = `http://your-frontend-url/reset-password?token=${resetToken}`; // Update with hosted frontend URL
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: username,
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
    const decoded = jwt.verify(token, ACCESS_TOKEN_SECRET);
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

// Get Users (for swiping) with Match Percentage, excluding matched users and liked users
app.get('/users', authenticateToken, async (req, res) => {
  try {
    const currentUser = await User.findById(req.user.id);
    // Fetch all matches involving the current user
    const matches = await Match.find({
      $or: [{ user1Id: req.user.id }, { user2Id: req.user.id }],
    });

    // Extract the IDs of matched users
    const matchedUserIds = matches.map(match =>
      match.user1Id.toString() === req.user.id.toString() ? match.user2Id : match.user1Id
    );

    // Get the IDs of users the current user has already liked
    const likedUserIds = currentUser.likes.map(id => id.toString());

    // Combine matched and liked user IDs to exclude
    const excludedUserIds = [...new Set([...matchedUserIds, ...likedUserIds])];

    // Fetch users, excluding the current user, matched users, and liked users
    const users = await User.find(
      {
        _id: { $ne: req.user.id, $nin: excludedUserIds },
      },
      'firstName lastName age bio gender interests photos'
    );

    const usersWithMatch = users.map(user => {
      const commonInterests = user.interests.filter(i => currentUser.interests.includes(i));
      const matchPercentage = Math.round((commonInterests.length / 5) * 100); // Max 5 interests
      return { ...user._doc, matchPercentage };
    });

    res.json(usersWithMatch);
  } catch (err) {
    console.error('Error fetching users:', err);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// Post Likes
app.post('/likes', authenticateToken, async (req, res) => {
  const { userId } = req.body;
  if (!userId) {
    return res.status(400).json({ error: 'userId is required' });
  }

  try {
    const liker = await User.findById(req.user.id);
    const likedUser = await User.findById(userId);

    if (!likedUser) {
      return res.status(404).json({ error: 'Liked user not found' });
    }

    if (!liker.likes.includes(userId)) {
      liker.likes.push(userId);
      await liker.save();
    }

    const isMatch = likedUser.likes.includes(req.user.id);

    if (isMatch) {
      // Create a match in the matches collection
      await Match.create({
        user1Id: req.user.id,
        user2Id: userId,
      });

      // Remove the likes since they've matched
      liker.likes = liker.likes.filter(id => id.toString() !== userId.toString());
      likedUser.likes = likedUser.likes.filter(id => id.toString() !== req.user.id.toString());
      await liker.save();
      await likedUser.save();
    }

    res.status(201).json({
      message: 'Liked',
      match: isMatch,
    });
  } catch (err) {
    console.error('Error posting like:', err);
    res.status(500).json({ error: 'Failed to like user' });
  }
});

// Get Matches
app.get('/matches', authenticateToken, async (req, res) => {
  try {
    // Fetch all matches involving the current user
    const matches = await Match.find({
      $or: [{ user1Id: req.user.id }, { user2Id: req.user.id }],
    });

    // Extract the IDs of matched users
    const matchedUserIds = matches.map(match =>
      match.user1Id.toString() === req.user.id.toString() ? match.user2Id : match.user1Id
    );

    // Fetch the matched users
    const matchedUsers = await User.find(
      { _id: { $in: matchedUserIds } },
      'firstName lastName age bio photos'
    );

    res.json(matchedUsers);
  } catch (err) {
    console.error('Error fetching matches:', err);
    res.status(500).json({ error: 'Failed to fetch matches' });
  }
});

// Get All Messages for the Current User
app.get('/messages', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    // Fetch all messages where the user is either the sender or recipient
    const messages = await Message.find({
      $or: [
        { senderId: userId },
        { chatId: { $regex: `^${userId}:|:${userId}$` } }, // Match chatId containing userId
      ],
    }).sort({ timestamp: 1 });

    // Group messages by the other user in the conversation
    const groupedMessages = messages.reduce((acc, message) => {
      const [user1, user2] = message.chatId.split(':');
      const otherUserId = user1 === userId ? user2 : user1;
      if (!acc[otherUserId]) acc[otherUserId] = [];
      acc[otherUserId].push({
        chatId: message.chatId,
        senderId: message.senderId.toString(),
        text: message.text,
        timestamp: message.timestamp,
      });
      return acc;
    }, {});

    res.json(groupedMessages);
  } catch (err) {
    console.error('Error fetching all messages:', err);
    res.status(500).json({ error: 'Failed to fetch all messages' });
  }
});

// Get Messages for a Specific Chat
app.get('/messages/:userId', authenticateToken, async (req, res) => {
  const { userId } = req.params;
  const chatId = [req.user.id, userId].sort().join(':');
  try {
    const messages = await Message.find({ chatId }).sort({ timestamp: 1 });
    res.json(messages);
  } catch (err) {
    console.error('Error fetching messages:', err);
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

// Post Messages (still needed for initial HTTP request, but WebSocket handles real-time)
app.post('/messages/:userId', authenticateToken, async (req, res) => {
  const { userId } = req.params;
  const { text } = req.body;
  const chatId = [req.user.id, userId].sort().join(':');
  try {
    const message = new Message({
      chatId,
      senderId: req.user.id,
      text,
      timestamp: new Date(),
    });
    await message.save();
    res.status(201).json(message);
  } catch (err) {
    console.error('Error sending message:', err);
    res.status(500).json({ error: 'Failed to send message' });
  }
});

// Profile (Get and Update)
app.get('/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id, 'firstName lastName age bio gender interests photos');
    res.json(user);
  } catch (err) {
    console.error('Error fetching profile:', err);
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

app.post('/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    user.firstName = req.body.firstName || user.firstName;
    user.lastName = req.body.lastName || user.lastName;
    user.age = req.body.age || user.age;
    user.bio = req.body.bio || user.bio;
    user.gender = req.body.gender || user.gender;
    user.interests = req.body.interests || user.interests;
    user.photos = req.body.photos || user.photos;
    await user.save();
    res.json({
      firstName: user.firstName,
      lastName: user.lastName,
      age: user.age,
      bio: user.bio,
      gender: user.gender,
      interests: user.interests,
      photos: user.photos,
    });
  } catch (err) {
    console.error('Profile update error:', err);
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

// Get User by ID (for fetching chatted users)
app.get('/users/:id', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.params.id, 'firstName lastName age bio photos');
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(user);
  } catch (err) {
    console.error('Error fetching user:', err);
    res.status(500).json({ error: 'Failed to fetch user' });
  }
});

server.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});