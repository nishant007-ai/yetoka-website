const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const twilio = require('twilio');
const axios = require('axios');
const dotenv = require('dotenv');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const hpp = require('hpp');
const path = require('path');
const fs = require('fs'); // Added fs module

// Load environment variables
dotenv.config();

// Initialize Express
const app = express();
const PORT = process.env.PORT || 6000;

// Security Middleware
app.use(helmet());
app.use(mongoSanitize());
app.use(xss());
app.use(hpp());

// CORS Configuration
app.use(cors({
    origin: ['http://localhost:3000', 'http://127.0.0.1:5500', `http://localhost:${PORT}`],
    credentials: true
}));

// Body parser
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true }));

// ============= FIXED STATIC FILE SERVING =============
// Get absolute paths
const __dirname = path.resolve();
const projectRoot = process.cwd();

console.log('📂 Current working directory:', projectRoot);
console.log('📂 __dirname:', __dirname);

// Find frontend folder - check multiple possible locations
let frontendPath = null;
const possiblePaths = [
    path.join(projectRoot, 'frontend'),        // frontend in project root
    path.join(__dirname, 'frontend'),          // frontend in current dir
    path.join(projectRoot, '..', 'frontend'),  // frontend in parent
    path.join(projectRoot, '../frontend'),     // alternative parent path
];

for (const possiblePath of possiblePaths) {
    if (fs.existsSync(possiblePath)) {
        frontendPath = possiblePath;
        console.log('✅ Found frontend at:', frontendPath);
        console.log('📄 Files in frontend:', fs.readdirSync(frontendPath));
        break;
    }
}

if (!frontendPath) {
    console.log('❌ Frontend folder not found in any location!');
    console.log('📁 Checking project root files:', fs.readdirSync(projectRoot));
    
    // Create frontend folder if it doesn't exist
    frontendPath = path.join(projectRoot, 'frontend');
    fs.mkdirSync(frontendPath, { recursive: true });
    console.log('📁 Created frontend folder at:', frontendPath);
}

// Serve static files from frontend folder
app.use(express.static(frontendPath));

// Debug route to check static files
app.get('/api/debug', (req, res) => {
    res.json({
        success: true,
        message: 'Server debug info',
        data: {
            port: PORT,
            projectRoot: projectRoot,
            frontendPath: frontendPath,
            frontendExists: fs.existsSync(frontendPath),
            frontendFiles: frontendPath ? fs.readdirSync(frontendPath) : [],
            __dirname: __dirname,
            possiblePaths: possiblePaths
        }
    });
});

// Serve index.html for root route
app.get('/', (req, res) => {
    const indexPath = path.join(frontendPath, 'index5.html');
    
    if (fs.existsSync(indexPath)) {
        console.log(`📄 Serving index5.html from: ${indexPath}`);
        res.sendFile(indexPath);
    } else {
        console.log(`❌ index5.html not found at: ${indexPath}`);
        
        // Create a simple test page if index5.html doesn't exist
        const testHtml = `
            <!DOCTYPE html>
            <html>
            <head>
                <title>RideShare - Test Page</title>
                <style>
                    body { font-family: Arial, sans-serif; padding: 40px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; }
                    .container { max-width: 800px; margin: 0 auto; text-align: center; }
                    h1 { font-size: 48px; margin-bottom: 20px; }
                    .logo { font-size: 72px; margin-bottom: 30px; }
                    .status { background: white; color: #333; padding: 20px; border-radius: 10px; margin: 20px 0; text-align: left; }
                    .success { color: #10b981; }
                    .error { color: #ef4444; }
                    .info { color: #3b82f6; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="logo">🚗</div>
                    <h1>RideShare Backend is Running!</h1>
                    <p>Backend server is working correctly.</p>
                    
                    <div class="status">
                        <h2>Server Status</h2>
                        <p><strong class="success">✅ Backend:</strong> Running on port ${PORT}</p>
                        <p><strong class="info">📁 Frontend Path:</strong> ${frontendPath}</p>
                        <p><strong class="${fs.existsSync(frontendPath) ? 'success' : 'error'}">
                            ${fs.existsSync(frontendPath) ? '✅' : '❌'} Frontend Folder:</strong> 
                            ${fs.existsSync(frontendPath) ? 'Found' : 'Not Found'}
                        </p>
                        <p><strong class="${fs.existsSync(indexPath) ? 'success' : 'error'}">
                            ${fs.existsSync(indexPath) ? '✅' : '❌'} index5.html:</strong> 
                            ${fs.existsSync(indexPath) ? 'Found' : 'Not Found'}
                        </p>
                    </div>
                    
                    <div class="status">
                        <h2>Available Endpoints</h2>
                        <p><a href="/api/health" style="color: #3b82f6;">/api/health</a> - Health check</p>
                        <p><a href="/api/debug" style="color: #3b82f6;">/api/debug</a> - Debug info</p>
                        <p><a href="/api/auth/send-otp" style="color: #3b82f6;">/api/auth/send-otp</a> - Send OTP</p>
                    </div>
                    
                    <div class="status">
                        <h2>Troubleshooting</h2>
                        <p>1. Make sure index5.html is in the frontend folder</p>
                        <p>2. Check browser console for errors (F12)</p>
                        <p>3. Verify folder structure:</p>
                        <pre style="background: #f3f4f6; padding: 10px; border-radius: 5px; text-align: left;">
project/
├── frontend/
│   └── index5.html
├── backend/
│   └── server.js
└── package.json</pre>
                    </div>
                </div>
            </body>
            </html>
        `;
        
        res.send(testHtml);
    }
});

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
});
app.use('/api', limiter);

// ============= MODELS =============

// User Schema
const userSchema = new mongoose.Schema({
    phone: {
        type: String,
        required: [true, 'Phone number is required'],
        unique: true,
        trim: true,
        match: [/^[0-9]{10}$/, 'Please enter a valid 10-digit phone number'],
        index: true
    },
    name: {
        type: String,
        trim: true
    },
    email: {
        type: String,
        trim: true,
        lowercase: true,
        match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please enter a valid email']
    },
    role: {
        type: String,
        enum: ['passenger', 'driver'],
        default: 'passenger'
    },
    profilePhoto: String,
    aadhaarNumber: {
        type: String,
        match: [/^[0-9]{12}$/, 'Please enter a valid 12-digit Aadhaar number']
    },
    aadhaarVerified: {
        type: Boolean,
        default: false
    },
    address: {
        street: String,
        city: String,
        state: String,
        pincode: String,
        verified: {
            type: Boolean,
            default: false
        }
    },
    criminalCheck: {
        verified: {
            type: Boolean,
            default: false
        },
        verifiedAt: Date,
        verifiedBy: String
    },
    vehicle: {
        number: String,
        model: String,
        color: String,
        type: {
            type: String,
            enum: ['hatchback', 'sedan', 'suv', 'luxury', 'other']
        },
        verified: {
            type: Boolean,
            default: false
        }
    },
    wallet: {
        balance: {
            type: Number,
            default: 0
        },
        transactions: [{
            amount: Number,
            type: {
                type: String,
                enum: ['credit', 'debit']
            },
            description: String,
            reference: String,
            status: {
                type: String,
                enum: ['pending', 'completed', 'failed'],
                default: 'completed'
            },
            createdAt: {
                type: Date,
                default: Date.now
            }
        }]
    },
    rides: {
        completed: {
            type: Number,
            default: 0
        },
        asPassenger: {
            type: Number,
            default: 0
        },
        asDriver: {
            type: Number,
            default: 0
        }
    },
    rating: {
        average: {
            type: Number,
            default: 0,
            min: 0,
            max: 5
        },
        count: {
            type: Number,
            default: 0
        }
    },
    premium: {
        isPremium: {
            type: Boolean,
            default: false
        },
        purchasedAt: Date,
        expiresAt: Date,
        plan: String
    },
    preferences: {
        smoking: Boolean,
        pets: Boolean,
        music: Boolean,
        ac: Boolean,
        luggage: Boolean,
        food: Boolean
    },
    otp: {
        code: String,
        expiresAt: Date
    },
    isVerified: {
        type: Boolean,
        default: false
    },
    isActive: {
        type: Boolean,
        default: true
    },
    lastLogin: Date,
    createdAt: {
        type: Date,
        default: Date.now
    },
    updatedAt: {
        type: Date,
        default: Date.now
    }
});

userSchema.index({ 'address.city': 1 });
userSchema.index({ 'address.state': 1 });

// Update timestamp on save
userSchema.pre('save', function(next) {
    this.updatedAt = Date.now();
    next();
});

const User = mongoose.model('User', userSchema);

// Ride Schema
const rideSchema = new mongoose.Schema({
    driver: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    from: {
        city: String,
        address: String,
        coordinates: {
            lat: Number,
            lng: Number
        }
    },
    to: {
        city: String,
        address: String,
        coordinates: {
            lat: Number,
            lng: Number
        }
    },
    dateTime: {
        type: Date,
        required: true
    },
    vehicle: {
        type: String,
        required: true
    },
    seats: {
        total: {
            type: Number,
            required: true,
            min: 1,
            max: 7
        },
        available: {
            type: Number,
            required: true,
            min: 0
        }
    },
    price: {
        type: Number,
        required: true,
        min: 0
    },
    preferences: {
        smoking: {
            type: Boolean,
            default: false
        },
        pets: {
            type: Boolean,
            default: false
        },
        music: {
            type: Boolean,
            default: true
        },
        ac: {
            type: Boolean,
            default: true
        },
        luggage: {
            type: Boolean,
            default: false
        },
        food: {
            type: Boolean,
            default: false
        }
    },
    passengers: [{
        user: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User'
        },
        bookedAt: {
            type: Date,
            default: Date.now
        },
        status: {
            type: String,
            enum: ['booked', 'cancelled', 'completed'],
            default: 'booked'
        },
        paymentStatus: {
            type: String,
            enum: ['pending', 'paid', 'refunded'],
            default: 'pending'
        }
    }],
    status: {
        type: String,
        enum: ['scheduled', 'active', 'completed', 'cancelled'],
        default: 'scheduled'
    },
    instantBook: {
        type: Boolean,
        default: false
    },
    aiRecommendationScore: {
        type: Number,
        default: 0
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    updatedAt: {
        type: Date,
        default: Date.now
    }
});

// Indexes for rides
rideSchema.index({ 'from.city': 1, 'to.city': 1 });
rideSchema.index({ dateTime: 1 });
rideSchema.index({ driver: 1 });
rideSchema.index({ status: 1 });
rideSchema.index({ aiRecommendationScore: -1 });
rideSchema.index({ 'from.coordinates': '2dsphere' });

rideSchema.pre('save', function(next) {
    this.updatedAt = Date.now();
    next();
});

const Ride = mongoose.model('Ride', rideSchema);

// Booking Schema
const bookingSchema = new mongoose.Schema({
    ride: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Ride',
        required: true
    },
    passenger: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    seats: {
        type: Number,
        required: true,
        min: 1
    },
    totalAmount: {
        type: Number,
        required: true
    },
    payment: {
        method: {
            type: String,
            enum: ['wallet', 'upi', 'card', 'cash'],
            default: 'wallet'
        },
        transactionId: String,
        status: {
            type: String,
            enum: ['pending', 'completed', 'failed', 'refunded'],
            default: 'pending'
        }
    },
    status: {
        type: String,
        enum: ['confirmed', 'cancelled', 'completed', 'no-show'],
        default: 'confirmed'
    },
    cancellationReason: String,
    rating: {
        byPassenger: {
            stars: {
                type: Number,
                min: 1,
                max: 5
            },
            review: String,
            createdAt: Date
        },
        byDriver: {
            stars: {
                type: Number,
                min: 1,
                max: 5
            },
            review: String,
            createdAt: Date
        }
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

const Booking = mongoose.model('Booking', bookingSchema);

// OTP Verification Schema
const otpSchema = new mongoose.Schema({
    phone: {
        type: String,
        required: true,
        index: true
    },
    code: {
        type: String,
        required: true
    },
    type: {
        type: String,
        enum: ['login', 'verification', 'reset'],
        default: 'login'
    },
    expiresAt: {
        type: Date,
        required: true,
        index: { expireAfterSeconds: 300 } // Auto delete after 5 minutes
    },
    verified: {
        type: Boolean,
        default: false
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

const OTP = mongoose.model('OTP', otpSchema);

// Withdrawal Request Schema
const withdrawalSchema = new mongoose.Schema({
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    amount: {
        type: Number,
        required: true,
        min: 100 // Minimum withdrawal amount
    },
    bankDetails: {
        accountNumber: String,
        ifscCode: String,
        accountHolderName: String
    },
    status: {
        type: String,
        enum: ['pending', 'approved', 'rejected', 'processed'],
        default: 'pending'
    },
    rejectionReason: String,
    processedAt: Date,
    adminNotes: String,
    createdAt: {
        type: Date,
        default: Date.now
    }
});

const Withdrawal = mongoose.model('Withdrawal', withdrawalSchema);

// ============= UTILITY FUNCTIONS =============

// Generate JWT Token
const generateToken = (userId) => {
    return jwt.sign(
        { userId },
        process.env.JWT_SECRET || 'rideshare_secret_key_2024',
        { expiresIn: '7d' }
    );
};

// Send OTP via SMS (Mock - replace with actual SMS service)
const sendOTP = async (phone, otp) => {
    try {
        console.log(`OTP ${otp} sent to ${phone}`);
        return true;
    } catch (error) {
        console.error('Error sending OTP:', error);
        return false;
    }
};

// Generate random OTP
const generateOTP = () => {
    return Math.floor(100000 + Math.random() * 900000).toString();
};

// Calculate AI Recommendation Score
const calculateAIScore = (ride, user) => {
    let score = 0;
    
    const avgPrice = 500;
    const priceDiff = Math.abs(ride.price - avgPrice);
    score += Math.max(0, 100 - priceDiff);
    
    const rideHour = new Date(ride.dateTime).getHours();
    const preferredHour = 9;
    const hourDiff = Math.abs(rideHour - preferredHour);
    score += Math.max(0, 50 - (hourDiff * 10));
    
    score += user.rating.average * 20;
    
    if (ride.instantBook) score += 30;
    if (ride.vehicle.includes('suv') || ride.vehicle.includes('innova')) score += 20;
    if (ride.preferences.ac) score += 15;
    if (ride.preferences.music) score += 10;
    
    return Math.min(score, 100);
};

// Check profile completion
const checkProfileCompletion = (user) => {
    const requirements = {
        photo: !!user.profilePhoto,
        aadhaar: user.aadhaarVerified,
        address: user.address?.verified || false,
        criminal: user.criminalCheck?.verified || false,
        vehicle: user.role === 'passenger' ? true : (user.vehicle?.verified || false)
    };
    
    const completed = Object.values(requirements).filter(v => v).length;
    const total = Object.keys(requirements).length;
    
    return {
        requirements,
        percentage: Math.round((completed / total) * 100),
        isComplete: completed === total
    };
};

// ============= MIDDLEWARE =============

// Auth middleware
const authMiddleware = async (req, res, next) => {
    try {
        const token = req.header('Authorization')?.replace('Bearer ', '');
        
        if (!token) {
            return res.status(401).json({
                success: false,
                message: 'No authentication token, access denied'
            });
        }
        
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'rideshare_secret_key_2024');
        const user = await User.findById(decoded.userId);
        
        if (!user) {
            return res.status(401).json({
                success: false,
                message: 'User not found'
            });
        }
        
        if (!user.isActive) {
            return res.status(401).json({
                success: false,
                message: 'Account is deactivated'
            });
        }
        
        req.user = user;
        req.token = token;
        next();
    } catch (error) {
        res.status(401).json({
            success: false,
            message: 'Token is not valid'
        });
    }
};

// Profile gate middleware
const profileGateMiddleware = async (req, res, next) => {
    try {
        const profileStatus = checkProfileCompletion(req.user);
        
        if (!profileStatus.isComplete) {
            return res.status(403).json({
                success: false,
                message: 'Please complete your profile',
                profileStatus
            });
        }
        
        next();
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
};

// ============= ROUTES =============

// Health check
app.get('/api/health', (req, res) => {
    res.status(200).json({
        success: true,
        message: 'RideShare Backend is running',
        timestamp: new Date(),
        uptime: process.uptime(),
        database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
        frontend: {
            path: frontendPath,
            exists: fs.existsSync(frontendPath),
            files: frontendPath ? fs.readdirSync(frontendPath) : []
        }
    });
});

// ===== AUTHENTICATION ROUTES =====

// Send OTP
app.post('/api/auth/send-otp', async (req, res) => {
    try {
        const { phone } = req.body;
        
        if (!phone || phone.length !== 10) {
            return res.status(400).json({
                success: false,
                message: 'Please provide a valid 10-digit phone number'
            });
        }
        
        const otp = generateOTP();
        const expiresAt = new Date(Date.now() + 5 * 60 * 1000);
        
        await OTP.findOneAndUpdate(
            { phone },
            {
                phone,
                code: otp,
                expiresAt,
                verified: false,
                type: 'login'
            },
            { upsert: true, new: true }
        );
        
        const sent = await sendOTP(phone, otp);
        
        if (!sent) {
            return res.status(500).json({
                success: false,
                message: 'Failed to send OTP'
            });
        }
        
        res.status(200).json({
            success: true,
            message: 'OTP sent successfully',
        });
    } catch (error) {
        console.error('Send OTP error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
});

// Verify OTP and Login/Register
app.post('/api/auth/verify-otp', async (req, res) => {
    try {
        const { phone, otp } = req.body;
        
        if (!phone || !otp) {
            return res.status(400).json({
                success: false,
                message: 'Phone and OTP are required'
            });
        }
        
        const otpRecord = await OTP.findOne({
            phone,
            code: otp,
            expiresAt: { $gt: new Date() }
        });
        
        if (!otpRecord) {
            return res.status(400).json({
                success: false,
                message: 'Invalid or expired OTP'
            });
        }
        
        otpRecord.verified = true;
        await otpRecord.save();
        
        let user = await User.findOne({ phone });
        const isNewUser = !user;
        
        if (!user) {
            user = new User({
                phone,
                isVerified: true
            });
            await user.save();
        } else {
            user.isVerified = true;
            user.lastLogin = new Date();
            await user.save();
        }
        
        const token = generateToken(user._id);
        const profileStatus = checkProfileCompletion(user);
        
        res.status(200).json({
            success: true,
            message: isNewUser ? 'Registration successful' : 'Login successful',
            token,
            user: {
                id: user._id,
                phone: user.phone,
                name: user.name,
                email: user.email,
                role: user.role,
                profilePhoto: user.profilePhoto,
                walletBalance: user.wallet.balance,
                ridesCompleted: user.rides.completed,
                rating: user.rating.average,
                isPremium: user.premium.isPremium
            },
            profileStatus,
            isNewUser
        });
    } catch (error) {
        console.error('Verify OTP error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
});

// Get user profile
app.get('/api/user/profile', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user._id).select('-otp -__v');
        const profileStatus = checkProfileCompletion(user);
        
        res.status(200).json({
            success: true,
            user,
            profileStatus
        });
    } catch (error) {
        console.error('Get profile error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
});

// Update user profile
app.put('/api/user/profile', authMiddleware, async (req, res) => {
    try {
        const updates = req.body;
        
        delete updates._id;
        delete updates.phone;
        delete updates.wallet;
        delete updates.rides;
        delete updates.rating;
        delete updates.createdAt;
        
        const user = await User.findByIdAndUpdate(
            req.user._id,
            { $set: updates },
            { new: true, runValidators: true }
        ).select('-otp -__v');
        
        const profileStatus = checkProfileCompletion(user);
        
        res.status(200).json({
            success: true,
            message: 'Profile updated successfully',
            user,
            profileStatus
        });
    } catch (error) {
        console.error('Update profile error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
});

// Complete profile verification
app.post('/api/user/complete-verification', authMiddleware, async (req, res) => {
    try {
        const { aadhaarNumber, address, vehicle } = req.body;
        
        const updates = {};
        
        if (aadhaarNumber) {
            updates.aadhaarNumber = aadhaarNumber;
            updates.aadhaarVerified = true;
        }
        
        if (address) {
            updates.address = {
                ...address,
                verified: true
            };
        }
        
        if (vehicle && req.user.role === 'driver') {
            updates.vehicle = {
                ...vehicle,
                verified: true
            };
        }
        
        const user = await User.findByIdAndUpdate(
            req.user._id,
            { $set: updates },
            { new: true, runValidators: true }
        ).select('-otp -__v');
        
        user.criminalCheck = {
            verified: true,
            verifiedAt: new Date(),
            verifiedBy: 'System'
        };
        await user.save();
        
        const profileStatus = checkProfileCompletion(user);
        
        res.status(200).json({
            success: true,
            message: 'Verification completed successfully',
            user,
            profileStatus
        });
    } catch (error) {
        console.error('Complete verification error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
});

// Upload profile photo
app.post('/api/user/upload-photo', authMiddleware, async (req, res) => {
    try {
        const { photoUrl } = req.body;
        
        if (!photoUrl) {
            return res.status(400).json({
                success: false,
                message: 'Photo URL is required'
            });
        }
        
        const user = await User.findByIdAndUpdate(
            req.user._id,
            { $set: { profilePhoto: photoUrl } },
            { new: true }
        ).select('-otp -__v');
        
        const profileStatus = checkProfileCompletion(user);
        
        res.status(200).json({
            success: true,
            message: 'Profile photo updated successfully',
            user,
            profileStatus
        });
    } catch (error) {
        console.error('Upload photo error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
});

// Search rides
app.get('/api/rides/search', authMiddleware, async (req, res) => {
    try {
        const { from, to, date, passengers, minPrice, maxPrice, preferences } = req.query;
        
        const query = {
            status: 'scheduled',
            'seats.available': { $gte: parseInt(passengers) || 1 }
        };
        
        if (from) query['from.city'] = new RegExp(from, 'i');
        if (to) query['to.city'] = new RegExp(to, 'i');
        
        if (date) {
            const searchDate = new Date(date);
            const nextDay = new Date(searchDate);
            nextDay.setDate(nextDay.getDate() + 1);
            query.dateTime = { $gte: searchDate, $lt: nextDay };
        }
        
        if (minPrice || maxPrice) {
            query.price = {};
            if (minPrice) query.price.$gte = parseInt(minPrice);
            if (maxPrice) query.price.$lte = parseInt(maxPrice);
        }
        
        if (preferences) {
            const pref = JSON.parse(preferences);
            Object.keys(pref).forEach(key => {
                if (pref[key] === true) {
                    query[`preferences.${key}`] = true;
                }
            });
        }
        
        const rides = await Ride.find(query)
            .populate('driver', 'name profilePhoto rating.average vehicle aadhaarVerified criminalCheck.verified')
            .sort({ dateTime: 1, aiRecommendationScore: -1 })
            .limit(50);
        
        const ridesWithScore = await Promise.all(rides.map(async (ride) => {
            const aiScore = calculateAIScore(ride, ride.driver);
            ride.aiRecommendationScore = aiScore;
            await ride.save();
            return ride;
        }));
        
        ridesWithScore.sort((a, b) => b.aiRecommendationScore - a.aiRecommendationScore);
        
        res.status(200).json({
            success: true,
            count: ridesWithScore.length,
            rides: ridesWithScore
        });
    } catch (error) {
        console.error('Search rides error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
});

// Get ride details
app.get('/api/rides/:id', authMiddleware, async (req, res) => {
    try {
        const ride = await Ride.findById(req.params.id)
            .populate('driver', 'name profilePhoto rating.average rides.completed vehicle aadhaarVerified criminalCheck.verified')
            .populate('passengers.user', 'name profilePhoto rating.average');
        
        if (!ride) {
            return res.status(404).json({
                success: false,
                message: 'Ride not found'
            });
        }
        
        res.status(200).json({
            success: true,
            ride
        });
    } catch (error) {
        console.error('Get ride error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
});

// Publish a ride
app.post('/api/rides/publish', authMiddleware, profileGateMiddleware, async (req, res) => {
    try {
        const user = req.user;
        
        if (user.role !== 'driver') {
            return res.status(403).json({
                success: false,
                message: 'Only drivers can publish rides'
            });
        }
        
        const rideData = req.body;
        
        const ride = new Ride({
            driver: user._id,
            ...rideData,
            seats: {
                total: rideData.seats,
                available: rideData.seats
            },
            aiRecommendationScore: 0
        });
        
        await ride.save();
        
        const aiScore = calculateAIScore(ride, user);
        ride.aiRecommendationScore = aiScore;
        await ride.save();
        
        res.status(201).json({
            success: true,
            message: 'Ride published successfully',
            ride
        });
    } catch (error) {
        console.error('Publish ride error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
});

// Book a ride
app.post('/api/bookings/book', authMiddleware, profileGateMiddleware, async (req, res) => {
    try {
        const { rideId, seats } = req.body;
        const user = req.user;
        
        const ride = await Ride.findById(rideId);
        
        if (!ride) {
            return res.status(404).json({
                success: false,
                message: 'Ride not found'
            });
        }
        
        if (ride.driver.toString() === user._id.toString()) {
            return res.status(400).json({
                success: false,
                message: 'Cannot book your own ride'
            });
        }
        
        if (ride.seats.available < seats) {
            return res.status(400).json({
                success: false,
                message: 'Not enough seats available'
            });
        }
        
        if (ride.dateTime < new Date()) {
            return res.status(400).json({
                success: false,
                message: 'Cannot book past rides'
            });
        }
        
        const totalAmount = ride.price * seats;
        
        if (user.wallet.balance < totalAmount) {
            return res.status(400).json({
                success: false,
                message: 'Insufficient wallet balance'
            });
        }
        
        user.wallet.balance -= totalAmount;
        user.wallet.transactions.push({
            amount: totalAmount,
            type: 'debit',
            description: `Booking for ride from ${ride.from.city} to ${ride.to.city}`,
            reference: `BOOK-${Date.now()}`,
            status: 'completed'
        });
        
        const driver = await User.findById(ride.driver);
        driver.wallet.balance += totalAmount;
        driver.wallet.transactions.push({
            amount: totalAmount,
            type: 'credit',
            description: `Payment for ride booking from ${user.name}`,
            reference: `BOOK-${Date.now()}`,
            status: 'pending'
        });
        
        ride.seats.available -= seats;
        ride.passengers.push({
            user: user._id,
            bookedAt: new Date(),
            status: 'booked',
            paymentStatus: 'paid'
        });
        
        const booking = new Booking({
            ride: ride._id,
            passenger: user._id,
            seats,
            totalAmount,
            payment: {
                method: 'wallet',
                status: 'completed',
                transactionId: `TXN-${Date.now()}`
            },
            status: 'confirmed'
        });
        
        await Promise.all([
            user.save(),
            driver.save(),
            ride.save(),
            booking.save()
        ]);
        
        user.rides.asPassenger += 1;
        driver.rides.asDriver += 1;
        await Promise.all([user.save(), driver.save()]);
        
        res.status(201).json({
            success: true,
            message: 'Ride booked successfully',
            booking,
            ride
        });
    } catch (error) {
        console.error('Book ride error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
});

// Get wallet details
app.get('/api/wallet', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user._id).select('wallet premium.isPremium');
        
        res.status(200).json({
            success: true,
            wallet: {
                balance: user.wallet.balance,
                isPremium: user.premium.isPremium,
                transactions: user.wallet.transactions.slice(-20).reverse()
            }
        });
    } catch (error) {
        console.error('Get wallet error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
});

// Add money to wallet
app.post('/api/wallet/add-money', authMiddleware, async (req, res) => {
    try {
        const { amount, paymentMethod } = req.body;
        
        if (!amount || amount < 100) {
            return res.status(400).json({
                success: false,
                message: 'Minimum amount is ₹100'
            });
        }
        
        const user = req.user;
        user.wallet.balance += parseInt(amount);
        user.wallet.transactions.push({
            amount: parseInt(amount),
            type: 'credit',
            description: `Wallet top-up via ${paymentMethod}`,
            reference: `TOPUP-${Date.now()}`,
            status: 'completed'
        });
        
        await user.save();
        
        res.status(200).json({
            success: true,
            message: 'Money added successfully',
            newBalance: user.wallet.balance
        });
    } catch (error) {
        console.error('Add money error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
});

// Get AI recommendations
app.get('/api/ai/recommendations', authMiddleware, async (req, res) => {
    try {
        const user = req.user;
        
        const userBookings = await Booking.find({ passenger: user._id })
            .populate('ride')
            .sort({ createdAt: -1 })
            .limit(10);
        
        const frequentRoutes = {};
        userBookings.forEach(booking => {
            const route = `${booking.ride.from.city}-${booking.ride.to.city}`;
            frequentRoutes[route] = (frequentRoutes[route] || 0) + 1;
        });
        
        const userState = user.address?.state || 'Maharashtra';
        const popularRoutes = await Ride.aggregate([
            {
                $match: {
                    status: 'scheduled',
                    'from.state': userState,
                    dateTime: { $gte: new Date() }
                }
            },
            {
                $group: {
                    _id: { from: '$from.city', to: '$to.city' },
                    count: { $sum: 1 },
                    avgPrice: { $avg: '$price' }
                }
            },
            { $sort: { count: -1 } },
            { $limit: 5 }
        ]);
        
        const recommendations = await Ride.find({
            status: 'scheduled',
            dateTime: { $gte: new Date() },
            'seats.available': { $gte: 1 }
        })
        .populate('driver', 'name profilePhoto rating.average vehicle')
        .sort({ aiRecommendationScore: -1 })
        .limit(10);
        
        res.status(200).json({
            success: true,
            recommendations: {
                frequentRoutes: Object.entries(frequentRoutes)
                    .map(([route, count]) => ({
                        route: route.split('-'),
                        frequency: count
                    }))
                    .sort((a, b) => b.frequency - a.frequency)
                    .slice(0, 3),
                popularRoutes: popularRoutes.map(r => ({
                    from: r._id.from,
                    to: r._id.to,
                    rideCount: r.count,
                    avgPrice: Math.round(r.avgPrice)
                })),
                personalized: recommendations.map(r => ({
                    ride: r,
                    matchScore: r.aiRecommendationScore
                }))
            }
        });
    } catch (error) {
        console.error('AI recommendations error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
});

// ============= ERROR HANDLERS =============

// 404 handler
app.use('*', (req, res) => {
    // Try to serve index.html for any unknown routes (for SPA)
    const indexPath = path.join(frontendPath, 'index5.html');
    if (fs.existsSync(indexPath) && !req.path.startsWith('/api/')) {
        res.sendFile(indexPath);
    } else {
        res.status(404).json({
            success: false,
            message: 'Route not found'
        });
    }
});

// Error handler
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    
    res.status(err.status || 500).json({
        success: false,
        message: err.message || 'Internal server error',
        ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
    });
});

// ============= START SERVER =============

const startServer = async () => {
    try {
        // Connect to MongoDB
        await mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/rideshare', {
            useNewUrlParser: true,
            useUnifiedTopology: true
        });
        
        console.log('✅ MongoDB Connected Successfully');
        
        // Start the server
        const server = app.listen(PORT, () => {
            console.log(`🚀 RideShare Backend running on port ${PORT}`);
            console.log(`🔗 Health check: http://localhost:${PORT}/api/health`);
            console.log(`🌐 Frontend: http://localhost:${PORT}`);
            console.log(`📊 MongoDB: Connected`);
            console.log(`📁 Frontend path: ${frontendPath}`);
            
            // List available files
            if (fs.existsSync(frontendPath)) {
                const files = fs.readdirSync(frontendPath);
                console.log(`📄 Frontend files: ${files.join(', ')}`);
            }
        });

        // Graceful shutdown
        process.on('SIGTERM', () => {
            console.log('SIGTERM received. Shutting down gracefully...');
            server.close(() => {
                console.log('Server closed');
                mongoose.connection.close(false, () => {
                    console.log('MongoDB connection closed');
                    process.exit(0);
                });
            });
        });

    } catch (err) {
        console.error('❌ MongoDB Connection Error:', err);
        process.exit(1);
    }
};

// Start the server
startServer();