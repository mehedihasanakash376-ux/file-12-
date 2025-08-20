const express = require('express');
const mongoose = require('mongoose');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const { body, validationResult } = require('express-validator');
require('dotenv').config();

const app = express();

// Trust proxy for Render deployment
app.set('trust proxy', 1);

const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI;
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
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
  trustProxy: true
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

// Post Schema
const postSchema = new mongoose.Schema({
  user: {
    type: String,
    required: true,
    maxlength: 20
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
  comments: [{
    id: {
      type: String,
      default: () => new mongoose.Types.ObjectId().toString()
    },
    user: {
      type: String,
      required: true,
      maxlength: 20
    },
    text: {
      type: String,
      required: true,
      maxlength: 1000
    },
    parentId: {
      type: String,
      default: null
    },
    likes: {
      type: Number,
      default: 0
    },
    createdAt: {
      type: Date,
      default: Date.now
    }
  }],
  hashtags: [String],
  createdAt: {
    type: Date,
    default: Date.now
  }
});

const Post = mongoose.model('Post', postSchema);

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
    const allowedTypes = /jpeg|jpg|png|gif|webp|mp4|webm|avi|mov|mp3|wav|ogg|pdf|doc|docx|txt|zip|rar|7z/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = file.mimetype.startsWith('image/') || 
                    file.mimetype.startsWith('video/') || 
                    file.mimetype.startsWith('audio/') ||
                    ['application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'text/plain', 'application/zip', 'application/x-zip-compressed', 'application/x-rar-compressed', 'application/vnd.rar', 'application/x-7z-compressed', 'application/octet-stream'].includes(file.mimetype);
    
    if (mimetype && extname) {
      return cb(null, true);
    } else {
      console.log('Rejected file:', file.originalname, 'MIME:', file.mimetype, 'Ext:', path.extname(file.originalname));
      cb(new Error(`Invalid file type: ${file.mimetype}. Allowed types: images, videos, audio, PDF, DOC, TXT, ZIP, RAR, 7Z`));
    }
  }
});

// Routes

// Get platform statistics
app.get('/api/stats', async (req, res) => {
  try {
    const totalPosts = await Post.countDocuments();
    const totalLikes = await Post.aggregate([
      { $group: { _id: null, total: { $sum: '$likes' } } }
    ]);
    const totalFiles = await Post.aggregate([
      { $group: { _id: null, total: { $sum: { $size: '$media' } } } }
    ]);
    
    // Get unique users count
    const uniqueUsers = await Post.distinct('user');
    
    res.json({
      totalPosts,
      totalLikes: totalLikes[0]?.total || 0,
      totalFiles: totalFiles[0]?.total || 0,
      totalUsers: uniqueUsers.length
    });
  } catch (error) {
    console.error('Get stats error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get top liked posts
app.get('/api/posts/top', async (req, res) => {
  try {
    const { limit = 10 } = req.query;
    
    const posts = await Post.find()
      .sort({ likes: -1, createdAt: -1 })
      .limit(parseInt(limit));

    res.json(posts);
  } catch (error) {
    console.error('Get top posts error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Search users and posts
app.get('/api/search', async (req, res) => {
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
      // Get unique users from posts
      const userPosts = await Post.find({
        user: { $regex: searchQuery, $options: 'i' }
      }).distinct('user');
      
      users = userPosts.slice(skip, skip + limitNum).map(username => ({
        username,
        user: username
      }));
    }

    if (type === 'posts' || type === 'all') {
      posts = await Post.find({
        $or: [
          { text: { $regex: searchQuery, $options: 'i' } },
          { hashtags: { $in: [new RegExp(searchQuery, 'i')] } }
        ]
      })
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

// Create post
app.post('/api/posts', upload.array('files', 10), async (req, res) => {
  try {
    const { user, text } = req.body;
    
    if (!user || user.trim().length === 0) {
      return res.status(400).json({ error: 'Username is required' });
    }
    
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
      user: user.trim(),
      text: text || '',
      media,
      hashtags: hashtags.map(tag => tag.toLowerCase())
    });

    await post.save();

    res.status(201).json(post);
  } catch (error) {
    console.error('Create post error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get posts
app.get('/api/posts', async (req, res) => {
  try {
    const { page = 0, limit = 10, since } = req.query;
    
    let query = {};
    
    if (since) {
      query.createdAt = { $gt: new Date(since) };
    }

    const posts = await Post.find(query)
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .skip(parseInt(page) * parseInt(limit));

    res.json(posts);
  } catch (error) {
    console.error('Get posts error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Like post
app.post('/api/posts/:id/like', async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);
    if (!post) {
      return res.status(404).json({ error: 'Post not found' });
    }

    post.likes += 1;
    await post.save();

    res.json({ likes: post.likes });
  } catch (error) {
    console.error('Like post error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Add comment to post
app.post('/api/posts/:id/comments', async (req, res) => {
  try {
    const { user, text, parentId } = req.body;
    
    if (!user || !text) {
      return res.status(400).json({ error: 'User and text are required' });
    }
    
    if (user.length > 20 || text.length > 1000) {
      return res.status(400).json({ error: 'User or text too long' });
    }

    const post = await Post.findById(req.params.id);
    if (!post) {
      return res.status(404).json({ error: 'Post not found' });
    }

    const comment = {
      id: new mongoose.Types.ObjectId().toString(),
      user: user.trim(),
      text: text.trim(),
      parentId: parentId || null,
      likes: 0,
      createdAt: new Date()
    };

    post.comments.push(comment);
    await post.save();

    res.status(201).json(comment);
  } catch (error) {
    console.error('Add comment error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Like comment
app.post('/api/posts/:postId/comments/:commentId/like', async (req, res) => {
  try {
    const post = await Post.findById(req.params.postId);
    if (!post) {
      return res.status(404).json({ error: 'Post not found' });
    }

    const comment = post.comments.id(req.params.commentId);
    if (!comment) {
      return res.status(404).json({ error: 'Comment not found' });
    }

    comment.likes += 1;
    await post.save();

    res.json({ likes: comment.likes });
  } catch (error) {
    console.error('Like comment error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Delete comment (admin only)
app.delete('/api/posts/:postId/comments/:commentId', async (req, res) => {
  try {
    const { password } = req.body;
    
    if (password !== ADMIN_PASSWORD) {
      return res.status(401).json({ error: 'Invalid admin password' });
    }

    const post = await Post.findById(req.params.postId);
    if (!post) {
      return res.status(404).json({ error: 'Post not found' });
    }

    // Remove the comment and all its replies
    const commentId = req.params.commentId;
    const commentsToRemove = [commentId];
    
    // Find all replies to this comment (recursive)
    const findReplies = (parentId) => {
      post.comments.forEach(comment => {
        if (comment.parentId === parentId) {
          commentsToRemove.push(comment.id);
          findReplies(comment.id);
        }
      });
    };
    
    findReplies(commentId);
    
    // Remove all comments and replies
    post.comments = post.comments.filter(comment => !commentsToRemove.includes(comment.id));
    await post.save();

    res.json({ message: 'Comment and replies deleted successfully' });
  } catch (error) {
    console.error('Delete comment error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});
// Delete post (admin only for now)
app.delete('/api/posts/:id', async (req, res) => {
  try {
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

    res.json({ message: 'Post deleted successfully' });
  } catch (error) {
    console.error('Delete post error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

let registrationEnabled = true;

// Get registration status
app.get('/api/auth/registration-status', (req, res) => {
  res.json({ enabled: registrationEnabled });
});

// Toggle registration (admin only)
app.post('/api/admin/toggle-registration', async (req, res) => {
  try {
    const { password } = req.body;
    
    if (password !== ADMIN_PASSWORD) {
      return res.status(401).json({ error: 'Invalid admin password' });
    }
    
    registrationEnabled = !registrationEnabled;
    res.json({ enabled: registrationEnabled });
  } catch (error) {
    console.error('Toggle registration error:', error);
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
  if (req.path === '/post.html' || req.path === '/all.html' || req.path === '/profile.html' || 
      req.path === '/search.html' || req.path === '/admin.html') {
    return res.sendFile(path.join(__dirname, 'public', req.path));
  }
  
  // For /post, /all, /profile, /search, /admin routes, serve the HTML files
  if (req.path === '/post') {
    return res.sendFile(path.join(__dirname, 'public', 'post.html'));
  }
  
  if (req.path === '/all') {
    return res.sendFile(path.join(__dirname, 'public', 'all.html'));
  }
  
  if (req.path === '/profile') {
    return res.sendFile(path.join(__dirname, 'public', 'profile.html'));
  }
  
  if (req.path === '/search') {
    return res.sendFile(path.join(__dirname, 'public', 'search.html'));
  }
  
  if (req.path === '/admin') {
    return res.sendFile(path.join(__dirname, 'public', 'admin.html'));
  }
  
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = { app };