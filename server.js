const express = require('express');
const mongoose = require('mongoose');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const { body, validationResult } = require('express-validator');
const http = require('http');
const socketIo = require('socket.io');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// Trust proxy for Render deployment
app.set('trust proxy', true);

const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';

// Security middleware
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 200, // limit each IP to 200 requests per windowMs
  message: 'Too many requests from this IP, please try again later.'
});
app.use('/api/', limiter);

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(express.static('public'));

// Create uploads directory if it doesn't exist
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// Serve uploaded files with proper headers
app.use('/uploads', (req, res, next) => {
  res.header('Cross-Origin-Resource-Policy', 'cross-origin');
  next();
}, express.static('uploads'));

// MongoDB connection
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('Connected to MongoDB'))
.catch(err => console.error('MongoDB connection error:', err));

// User Schema
const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    minlength: 3,
    maxlength: 20,
    match: /^[a-zA-Z0-9_]+$/
  },
  password: {
    type: String,
    required: true,
    minlength: 6
  },
  email: {
    type: String,
    sparse: true,
    unique: true
  },
  avatar: {
    type: String,
    default: ''
  },
  bio: {
    type: String,
    maxlength: 200,
    default: ''
  },
  isPremium: {
    type: Boolean,
    default: false
  },
  isOnline: {
    type: Boolean,
    default: false
  },
  lastSeen: {
    type: Date,
    default: Date.now
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Auto-set premium status based on username first letter
userSchema.pre('save', function(next) {
  if (this.isNew) {
    const firstLetter = this.username.charAt(0).toLowerCase();
    const premiumLetters = ['n', 'm', 'x', 'p', 'a', 'o', 'b'];
    this.isPremium = premiumLetters.includes(firstLetter);
  }
  next();
});

const User = mongoose.model('User', userSchema);

// Post Schema (updated)
const postSchema = new mongoose.Schema({
  user: {
    type: String,
    required: true,
    maxlength: 20
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  text: {
    type: String,
    maxlength: 2000
  },
  media: [{
    filename: String,
    originalName: String,
    mimetype: String,
    size: Number,
    url: String
  }],
  likes: {
    type: Number,
    default: 0
  },
  likedBy: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }],
  reactions: {
    love: { type: Number, default: 0 },
    laugh: { type: Number, default: 0 },
    like: { type: Number, default: 0 },
    wow: { type: Number, default: 0 },
    sad: { type: Number, default: 0 },
    angry: { type: Number, default: 0 },
    total: { type: Number, default: 0 }
  },
  comments: [{
    _id: { type: mongoose.Schema.Types.ObjectId, auto: true },
    user: String,
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    text: String,
    likes: { type: Number, default: 0 },
    likedBy: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    createdAt: { type: Date, default: Date.now },
    replies: [{
      _id: { type: mongoose.Schema.Types.ObjectId, auto: true },
      user: String,
      userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
      text: String,
      likes: { type: Number, default: 0 },
      likedBy: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
      createdAt: { type: Date, default: Date.now }
    }]
  }],
  hashtags: [String],
  createdAt: {
    type: Date,
    default: Date.now
  }
});

const Post = mongoose.model('Post', postSchema);

// Chat Schema
const chatSchema = new mongoose.Schema({
  participants: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  }],
  lastMessage: {
    type: String,
    default: ''
  },
  lastMessageTime: {
    type: Date,
    default: Date.now
  },
  isGroup: {
    type: Boolean,
    default: false
  },
  groupName: String,
  groupAvatar: String,
  createdAt: {
    type: Date,
    default: Date.now
  }
});

const Chat = mongoose.model('Chat', chatSchema);

// Message Schema
const messageSchema = new mongoose.Schema({
  chatId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Chat',
    required: true
  },
  sender: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  content: {
    type: String,
    required: true
  },
  messageType: {
    type: String,
    enum: ['text', 'image', 'video', 'audio', 'file'],
    default: 'text'
  },
  media: {
    filename: String,
    originalName: String,
    mimetype: String,
    size: Number,
    url: String
  },
  readBy: [{
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    readAt: { type: Date, default: Date.now }
  }],
  createdAt: {
    type: Date,
    default: Date.now
  }
});

const Message = mongoose.model('Message', messageSchema);

// Multer configuration for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 50 * 1024 * 1024, // 50MB limit
    files: 10 // Max 10 files per upload
  },
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif|webp|mp4|webm|avi|mov|mp3|wav|ogg|pdf|doc|docx|txt|zip|rar/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = file.mimetype.startsWith('image/') || 
                    file.mimetype.startsWith('video/') || 
                    file.mimetype.startsWith('audio/') ||
                    ['application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'text/plain', 'application/zip', 'application/x-rar-compressed'].includes(file.mimetype);
    
    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb(new Error('Invalid file type'));
    }
  }
});

// Authentication middleware
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user) {
      return res.status(401).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid token' });
  }
};

// Optional authentication middleware
const optionalAuth = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token) {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      const user = await User.findById(decoded.userId);
      if (user) {
        req.user = user;
      }
    } catch (error) {
      // Token invalid, continue without user
    }
  }
  next();
};

// Socket.IO connection handling
const connectedUsers = new Map();

io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  // User authentication for socket
  socket.on('authenticate', async (token) => {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      const user = await User.findById(decoded.userId);
      if (user) {
        socket.userId = user._id.toString();
        socket.username = user.username;
        connectedUsers.set(user._id.toString(), socket.id);
        
        // Update user online status
        await User.findByIdAndUpdate(user._id, { 
          isOnline: true,
          lastSeen: new Date()
        });
        
        socket.on('webrtc-offer', (data) => {
          const { targetUserId, offer } = data;
          const targetSocketId = connectedUsers.get(targetUserId);
          
          if (targetSocketId) {
            io.to(targetSocketId).emit('webrtc-offer', {
              offer,
              senderId: socket.userId
            });
          }
        });
        
        socket.on('webrtc-answer', (data) => {
          const { targetUserId, answer } = data;
          const targetSocketId = connectedUsers.get(targetUserId);
          
          if (targetSocketId) {
            io.to(targetSocketId).emit('webrtc-answer', {
              answer,
              senderId: socket.userId
            });
          }
        });
        
        socket.on('webrtc-ice-candidate', (data) => {
          const { targetUserId, candidate } = data;
          const targetSocketId = connectedUsers.get(targetUserId);
          
          if (targetSocketId) {
            io.to(targetSocketId).emit('webrtc-ice-candidate', {
              candidate,
              senderId: socket.userId
            });
          }
        });

        socket.emit('authenticated', { user: user.username });
        
        // Broadcast user online status
        socket.broadcast.emit('userOnline', { 
          userId: user._id,
          username: user.username 
        });
      }
    } catch (error) {
      socket.emit('authError', { error: 'Invalid token' });
    }
  });

  // Join chat room
  socket.on('joinChat', (chatId) => {
    socket.join(chatId);
    console.log(`User ${socket.username} joined chat ${chatId}`);
  });

  // Leave chat room
  socket.on('leaveChat', (chatId) => {
    socket.leave(chatId);
    console.log(`User ${socket.username} left chat ${chatId}`);
  });

  // Handle new message
  socket.on('sendMessage', async (data) => {
    try {
      const { chatId, content, messageType = 'text' } = data;
      
      if (!socket.userId) {
        socket.emit('error', { message: 'Not authenticated' });
        return;
      }

      const message = new Message({
        chatId,
        sender: socket.userId,
        content,
        messageType
      });

      await message.save();
      await message.populate('sender', 'username isPremium avatar');

      // Update chat last message
      await Chat.findByIdAndUpdate(chatId, {
        lastMessage: content,
        lastMessageTime: new Date()
      });

      // Emit to all users in the chat
      io.to(chatId).emit('newMessage', {
        _id: message._id,
        chatId: message.chatId,
        sender: message.sender,
        content: message.content,
        messageType: message.messageType,
        createdAt: message.createdAt
      });

    } catch (error) {
      console.error('Error sending message:', error);
      socket.emit('error', { message: 'Failed to send message' });
    }
  });

  // Handle typing indicator
  socket.on('typing', (data) => {
    socket.to(data.chatId).emit('userTyping', {
      userId: socket.userId,
      username: socket.username,
      isTyping: data.isTyping
    });
  });

  // Handle voice call initiation
  socket.on('initiateCall', (data) => {
    const { targetUserId, callType } = data;
    const targetSocketId = connectedUsers.get(targetUserId);
    
    if (targetSocketId) {
      io.to(targetSocketId).emit('incomingCall', {
        callerId: socket.userId,
        callerName: socket.username,
        callType
      });
    }
  });

  // Handle call response
  socket.on('callResponse', (data) => {
    const { callerId, accepted } = data;
    const callerSocketId = connectedUsers.get(callerId);
    
    if (callerSocketId) {
      io.to(callerSocketId).emit('callResponse', {
        accepted,
        responderId: socket.userId,
        responderName: socket.username
      });
    }
  });

  // Handle WebRTC signaling
  socket.on('webrtc-offer', (data) => {
    const { targetUserId, offer } = data;
    const targetSocketId = connectedUsers.get(targetUserId);
    
    if (targetSocketId) {
      io.to(targetSocketId).emit('webrtc-offer', {
        offer,
        senderId: socket.userId
      });
    }
  });
  
  socket.on('webrtc-answer', (data) => {
    const { targetUserId, answer } = data;
    const targetSocketId = connectedUsers.get(targetUserId);
    
    if (targetSocketId) {
      io.to(targetSocketId).emit('webrtc-answer', {
        answer,
        senderId: socket.userId
      });
    }
  });
  
  socket.on('webrtc-ice-candidate', (data) => {
    const { targetUserId, candidate } = data;
    const targetSocketId = connectedUsers.get(targetUserId);
    
    if (targetSocketId) {
      io.to(targetSocketId).emit('webrtc-ice-candidate', {
        candidate,
        senderId: socket.userId
      });
    }
  });

  // Handle disconnect
  socket.on('disconnect', async () => {
    console.log('User disconnected:', socket.id);
    
    if (socket.userId) {
      connectedUsers.delete(socket.userId);
      
      // Update user offline status
      await User.findByIdAndUpdate(socket.userId, { 
        isOnline: false,
        lastSeen: new Date()
      });

      // Broadcast user offline status
      socket.broadcast.emit('userOffline', { 
        userId: socket.userId,
        username: socket.username 
      });
    }
  });
});

// Routes

// Check username availability
app.get('/api/auth/check-username/:username', async (req, res) => {
  try {
    const { username } = req.params;
    
    if (username.length < 3 || username.length > 20) {
      return res.json({ available: false, message: 'Username must be 3-20 characters' });
    }
    
    if (!/^[a-zA-Z0-9_]+$/.test(username)) {
      return res.json({ available: false, message: 'Username can only contain letters, numbers, and underscores' });
    }
    
    const existingUser = await User.findOne({ username: username.toLowerCase() });
    res.json({ 
      available: !existingUser,
      message: existingUser ? 'Username already taken' : 'Username available'
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Register user
app.post('/api/auth/register', [
  body('username').isLength({ min: 3, max: 20 }).matches(/^[a-zA-Z0-9_]+$/),
  body('password').isLength({ min: 6 })
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { username, password, email } = req.body;
    
    // Check if user already exists
    const existingUser = await User.findOne({ 
      $or: [
        { username: username.toLowerCase() },
        { email: email }
      ]
    });
    
    if (existingUser) {
      return res.status(400).json({ error: 'Username or email already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Create user
    const user = new User({
      username: username.toLowerCase(),
      password: hashedPassword,
      email: email || undefined
    });

    await user.save();

    // Generate JWT token
    const token = jwt.sign(
      { userId: user._id, username: user.username },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.status(201).json({
      message: 'User created successfully',
      token,
      user: {
        id: user._id,
        username: user.username,
        isPremium: user.isPremium,
        avatar: user.avatar,
        bio: user.bio
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Login user
app.post('/api/auth/login', [
  body('username').notEmpty(),
  body('password').notEmpty()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { username, password } = req.body;
    
    // Find user
    const user = await User.findOne({ username: username.toLowerCase() });
    if (!user) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    // Update last seen
    user.lastSeen = new Date();
    await user.save();

    // Generate JWT token
    const token = jwt.sign(
      { userId: user._id, username: user.username },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        username: user.username,
        isPremium: user.isPremium,
        avatar: user.avatar,
        bio: user.bio,
        email: user.email
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get current user
app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    res.json({
      user: {
        id: req.user._id,
        username: req.user.username,
        isPremium: req.user.isPremium,
        avatar: req.user.avatar,
        bio: req.user.bio,
        email: req.user.email,
        isOnline: req.user.isOnline,
        lastSeen: req.user.lastSeen
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Search users and posts
app.get('/api/search', optionalAuth, async (req, res) => {
  try {
    const { q, type = 'all', page = 0, limit = 10 } = req.query;
    
    if (!q || q.trim().length < 2) {
      return res.json({ users: [], posts: [] });
    }

    const searchQuery = q.trim();
    const skip = parseInt(page) * parseInt(limit);
    const limitNum = parseInt(limit);

    let users = [];
    let posts = [];

    if (type === 'users' || type === 'all') {
      let userQuery = {
        username: { $regex: searchQuery, $options: 'i' }
      };
      
      // Exclude current user from search results
      if (req.user) {
        userQuery._id = { $ne: req.user._id };
      }
      
      users = await User.find(userQuery)
      .select('_id username isPremium avatar bio isOnline lastSeen')
      .limit(limitNum)
      .skip(skip)
      .sort({ isPremium: -1, username: 1 });
    }

    if (type === 'posts' || type === 'all') {
      posts = await Post.find({
        $or: [
          { text: { $regex: searchQuery, $options: 'i' } },
          { hashtags: { $in: [new RegExp(searchQuery, 'i')] } }
        ]
      })
      .populate('userId', 'username isPremium avatar')
      .limit(limitNum)
      .skip(skip)
      .sort({ createdAt: -1 });
    }

    res.json({ users, posts });
  } catch (error) {
    console.error('Search error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get user profile and posts
app.get('/api/users/:username', optionalAuth, async (req, res) => {
  try {
    const { username } = req.params;
    const { page = 0, limit = 10 } = req.query;
    
    const user = await User.findOne({ username: username.toLowerCase() })
      .select('username isPremium avatar bio isOnline lastSeen createdAt');
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const posts = await Post.find({ userId: user._id })
      .populate('userId', 'username isPremium avatar')
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .skip(parseInt(page) * parseInt(limit));

    const totalPosts = await Post.countDocuments({ userId: user._id });

    res.json({
      user,
      posts,
      totalPosts,
      hasMore: (parseInt(page) + 1) * parseInt(limit) < totalPosts
    });
  } catch (error) {
    console.error('Get user profile error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Create post
app.post('/api/posts', upload.array('files', 10), async (req, res) => {
  try {
    // Check for authentication token
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ error: 'Access token required' });
    }

    let user;
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      user = await User.findById(decoded.userId);
      if (!user) {
        return res.status(401).json({ error: 'Invalid token' });
      }
    } catch (error) {
      return res.status(403).json({ error: 'Invalid token' });
    }

    const { text } = req.body;
    
    // Handle both files and file fields
    const uploadedFiles = [];
    if (req.files && req.files.length > 0) {
      uploadedFiles.push(...req.files);
    }
    
    if (!text && uploadedFiles.length === 0) {
      return res.status(400).json({ error: 'Post must contain text or media' });
    }

    // Extract hashtags
    const hashtags = text ? text.match(/#\w+/g) || [] : [];

    // Process uploaded files
    const media = uploadedFiles.map(file => ({
      filename: file.filename,
      originalName: file.originalname,
      mimetype: file.mimetype,
      size: file.size,
      url: `/uploads/${file.filename}`
    }));

    const post = new Post({
      user: user.username,
      userId: user._id,
      text: text || '',
      media,
      hashtags: hashtags.map(tag => tag.toLowerCase())
    });

    await post.save();
    await post.populate('userId', 'username isPremium avatar');

    // Emit new post to all connected clients
    io.emit('newPost', post);

    res.status(201).json(post);
  } catch (error) {
    console.error('Create post error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get posts
app.get('/api/posts', optionalAuth, async (req, res) => {
  try {
    const { page = 0, limit = 10, userId, since } = req.query;
    
    let query = {};
    if (userId) {
      query.userId = userId;
    }
    
    if (since) {
      query.createdAt = { $gt: new Date(since) };
    }

    const posts = await Post.find(query)
      .populate('userId', 'username isPremium avatar')
      .populate('comments.userId', 'username isPremium avatar')
      .populate('comments.replies.userId', 'username isPremium avatar')
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .skip(parseInt(page) * parseInt(limit));

    // Add user interaction data if authenticated
    if (req.user) {
      posts.forEach(post => {
        post.userLiked = post.likedBy.includes(req.user._id);
        post.comments.forEach(comment => {
          comment.userLiked = comment.likedBy.includes(req.user._id);
          comment.replies.forEach(reply => {
            reply.userLiked = reply.likedBy.includes(req.user._id);
          });
        });
      });
    }

    res.json(posts);
  } catch (error) {
    console.error('Get posts error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Like post
app.post('/api/posts/:id/like', authenticateToken, async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);
    if (!post) {
      return res.status(404).json({ error: 'Post not found' });
    }

    const userLiked = post.likedBy.includes(req.user._id);
    
    if (userLiked) {
      post.likedBy.pull(req.user._id);
      post.likes = Math.max(0, post.likes - 1);
    } else {
      post.likedBy.push(req.user._id);
      post.likes += 1;
    }

    await post.save();

    // Emit like update to all clients
    io.emit('postLiked', {
      postId: post._id,
      likes: post.likes,
      userId: req.user._id,
      liked: !userLiked
    });

    res.json({ likes: post.likes, liked: !userLiked });
  } catch (error) {
    console.error('Like post error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Add comment
app.post('/api/posts/:id/comments', authenticateToken, async (req, res) => {
  try {
    const { text } = req.body;
    
    if (!text || text.trim().length === 0) {
      return res.status(400).json({ error: 'Comment text is required' });
    }

    const post = await Post.findById(req.params.id);
    if (!post) {
      return res.status(404).json({ error: 'Post not found' });
    }

    const comment = {
      user: req.user.username,
      userId: req.user._id,
      text: text.trim(),
      createdAt: new Date()
    };

    post.comments.push(comment);
    await post.save();
    await post.populate('comments.userId', 'username isPremium avatar');

    const newComment = post.comments[post.comments.length - 1];

    // Emit new comment to all clients
    io.emit('newComment', {
      postId: post._id,
      comment: newComment
    });

    res.status(201).json(newComment);
  } catch (error) {
    console.error('Add comment error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Delete post
app.delete('/api/posts/:id', authenticateToken, async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);
    if (!post) {
      return res.status(404).json({ error: 'Post not found' });
    }

    // Check if user owns the post
    if (post.userId.toString() !== req.user._id.toString()) {
      return res.status(403).json({ error: 'Not authorized to delete this post' });
    }

    // Delete associated files
    if (post.media && post.media.length > 0) {
      post.media.forEach(file => {
        const filePath = path.join(__dirname, 'uploads', file.filename);
        if (fs.existsSync(filePath)) {
          fs.unlinkSync(filePath);
        }
      });
    }

    await Post.findByIdAndDelete(req.params.id);

    // Emit post deletion to all clients
    io.emit('postDeleted', { postId: post._id });

    res.json({ message: 'Post deleted successfully' });
  } catch (error) {
    console.error('Delete post error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Chat routes

// Get user's chats
app.get('/api/chats', authenticateToken, async (req, res) => {
  try {
    const chats = await Chat.find({
      participants: req.user._id
    })
    .populate('participants', 'username isPremium avatar isOnline lastSeen')
    .sort({ lastMessageTime: -1 });

    res.json(chats);
  } catch (error) {
    console.error('Get chats error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Create or get chat
app.post('/api/chats', authenticateToken, async (req, res) => {
  try {
    const { participantId } = req.body;
    
    if (!participantId) {
      return res.status(400).json({ error: 'Participant ID is required' });
    }

    // Check if chat already exists
    let chat = await Chat.findOne({
      participants: { $all: [req.user._id, participantId] },
      isGroup: false
    }).populate('participants', 'username isPremium avatar isOnline lastSeen');

    if (!chat) {
      // Create new chat
      chat = new Chat({
        participants: [req.user._id, participantId]
      });
      await chat.save();
      await chat.populate('participants', 'username isPremium avatar isOnline lastSeen');
    }

    res.json(chat);
  } catch (error) {
    console.error('Create chat error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get chat messages
app.get('/api/chats/:chatId/messages', authenticateToken, async (req, res) => {
  try {
    const { chatId } = req.params;
    const { page = 0, limit = 50 } = req.query;

    // Verify user is participant in chat
    const chat = await Chat.findOne({
      _id: chatId,
      participants: req.user._id
    });

    if (!chat) {
      return res.status(404).json({ error: 'Chat not found' });
    }

    const messages = await Message.find({ chatId })
      .populate('sender', 'username isPremium avatar')
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .skip(parseInt(page) * parseInt(limit));

    res.json(messages.reverse());
  } catch (error) {
    console.error('Get messages error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Send message to chat
app.post('/api/chats/:chatId/messages', authenticateToken, upload.single('file'), async (req, res) => {
  try {
    const { chatId } = req.params;
    const { content, messageType = 'text' } = req.body;
    
    // Verify user is participant in chat
    const chat = await Chat.findOne({
      _id: chatId,
      participants: req.user._id
    });

    if (!chat) {
      return res.status(404).json({ error: 'Chat not found' });
    }

    let media = null;
    if (req.file) {
      media = {
        filename: req.file.filename,
        originalName: req.file.originalname,
        mimetype: req.file.mimetype,
        size: req.file.size,
        url: `/uploads/${req.file.filename}`
      };
    }

    const message = new Message({
      chatId,
      sender: req.user._id,
      content: content || (media ? `Sent ${media.originalName}` : ''),
      messageType,
      media
    });

    await message.save();
    await message.populate('sender', 'username isPremium avatar');

    // Update chat last message
    await Chat.findByIdAndUpdate(chatId, {
      lastMessage: message.content,
      lastMessageTime: new Date()
    });

    // Emit to all users in the chat via socket
    io.to(chatId).emit('newMessage', {
      _id: message._id,
      chatId: message.chatId,
      sender: message.sender,
      content: message.content,
      messageType: message.messageType,
      media: message.media,
      createdAt: message.createdAt
    });

    res.status(201).json(message);
  } catch (error) {
    console.error('Send message error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Add reaction to post
app.post('/api/posts/:id/reactions', authenticateToken, async (req, res) => {
  try {
    const { type } = req.body;
    const validTypes = ['love', 'laugh', 'like', 'wow', 'sad', 'angry'];
    
    if (!validTypes.includes(type)) {
      return res.status(400).json({ error: 'Invalid reaction type' });
    }

    const post = await Post.findById(req.params.id);
    if (!post) {
      return res.status(404).json({ error: 'Post not found' });
    }

    // Initialize reactions if not exists
    if (!post.reactions) {
      post.reactions = {
        love: 0, laugh: 0, like: 0, wow: 0, sad: 0, angry: 0, total: 0
      };
    }

    post.reactions[type] += 1;
    post.reactions.total += 1;
    await post.save();

    res.json({ reactions: post.reactions });
  } catch (error) {
    console.error('Add reaction error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Add reply to comment
app.post('/api/posts/:postId/comments/:commentId/replies', authenticateToken, async (req, res) => {
  try {
    const { postId, commentId } = req.params;
    const { text } = req.body;
    
    if (!text || text.trim().length === 0) {
      return res.status(400).json({ error: 'Reply text is required' });
    }

    const post = await Post.findById(postId);
    if (!post) {
      return res.status(404).json({ error: 'Post not found' });
    }

    const comment = post.comments.id(commentId);
    if (!comment) {
      return res.status(404).json({ error: 'Comment not found' });
    }

    const reply = {
      user: req.user.username,
      userId: req.user._id,
      text: text.trim(),
      createdAt: new Date()
    };

    comment.replies.push(reply);
    await post.save();
    await post.populate('comments.replies.userId', 'username isPremium avatar');

    const newReply = comment.replies[comment.replies.length - 1];
    res.status(201).json(newReply);
  } catch (error) {
    console.error('Add reply error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Like comment
app.post('/api/posts/:postId/comments/:commentId/like', authenticateToken, async (req, res) => {
  try {
    const { postId, commentId } = req.params;
    
    const post = await Post.findById(postId);
    if (!post) {
      return res.status(404).json({ error: 'Post not found' });
    }

    const comment = post.comments.id(commentId);
    if (!comment) {
      return res.status(404).json({ error: 'Comment not found' });
    }

    const userLiked = comment.likedBy.includes(req.user._id);
    
    if (!userLiked) {
      comment.likedBy.push(req.user._id);
      comment.likes += 1;
    }

    await post.save();
    res.json({ likes: comment.likes, liked: true });
  } catch (error) {
    console.error('Like comment error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Admin routes
app.post('/api/admin/posts', async (req, res) => {
  try {
    const { password } = req.body;
    
    if (password !== ADMIN_PASSWORD) {
      return res.status(401).json({ error: 'Invalid admin password' });
    }

    const posts = await Post.find()
      .populate('userId', 'username isPremium avatar')
      .sort({ createdAt: -1 })
      .limit(100);

    res.json(posts);
  } catch (error) {
    console.error('Admin get posts error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/admin/posts/:id', async (req, res) => {
  try {
    const { password } = req.body;
    
    if (password !== ADMIN_PASSWORD) {
      return res.status(401).json({ error: 'Invalid admin password' });
    }

    const post = await Post.findById(req.params.id);
    if (!post) {
      return res.status(404).json({ error: 'Post not found' });
    }

    // Delete associated files
    if (post.media && post.media.length > 0) {
      post.media.forEach(file => {
        const filePath = path.join(__dirname, 'uploads', file.filename);
        if (fs.existsSync(filePath)) {
          fs.unlinkSync(filePath);
        }
      });
    }

    await Post.findByIdAndDelete(req.params.id);

    // Emit post deletion to all clients
    io.emit('postDeleted', { postId: post._id });

    res.json({ message: 'Post deleted successfully' });
  } catch (error) {
    console.error('Admin delete post error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Error:', error);
  
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ error: 'File too large. Maximum size is 50MB.' });
    }
    if (error.code === 'LIMIT_FILE_COUNT') {
      return res.status(400).json({ error: 'Too many files. Maximum is 10 files per upload.' });
    }
  }
  
  res.status(500).json({ error: 'Something went wrong!' });
});

// Catch-all route for SPA
app.get('*', (req, res) => {
  // Don't serve index.html for API routes or file uploads
  if (req.path.startsWith('/api/') || req.path.startsWith('/uploads/')) {
    return res.status(404).json({ error: 'Not found' });
  }
  
  // Serve specific HTML files
  if (req.path === '/auth.html' || req.path === '/chat.html' || req.path === '/search.html' || 
      req.path === '/profile.html' || req.path === '/all.html' || req.path === '/info.html' || 
      req.path === '/admin.html') {
    return res.sendFile(path.join(__dirname, 'public', req.path));
  }
  
  // For /info and /admin routes, serve the HTML files
  if (req.path === '/info') {
    return res.sendFile(path.join(__dirname, 'public', 'info.html'));
  }
  
  if (req.path === '/admin') {
    return res.sendFile(path.join(__dirname, 'public', 'admin.html'));
  }
  
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = { app, server, io };