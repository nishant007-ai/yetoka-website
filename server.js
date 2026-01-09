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
    origin: ['http://localhost:3000', 'http://127.0.0.1:5500'],
    credentials: true
}));

// Body parser
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true }));

// Serve frontend files
app.use(express.static(path.join(__dirname, '../frontend')));

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
        index: true // ✅ Only define index here
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

// ✅ Removed duplicate indexes - only using schema-level indexes
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

// ✅ Schema-level indexes only
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
        index: true // ✅ Only schema-level index
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
        // Mock implementation - replace with actual SMS service like Twilio
        console.log(`OTP ${otp} sent to ${phone}`);
        
        // Uncomment for actual Twilio integration
        /*
        const client = twilio(
            process.env.TWILIO_SID,
            process.env.TWILIO_AUTH_TOKEN
        );
        
        await client.messages.create({
            body: `Your RideShare OTP is: ${otp}. Valid for 5 minutes.`,
            from: process.env.TWILIO_PHONE,
            to: `+91${phone}`
        });
        */
        
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
    
    // 1. Price scoring (lower is better)
    const avgPrice = 500; // Average price for the route
    const priceDiff = Math.abs(ride.price - avgPrice);
    score += Math.max(0, 100 - priceDiff);
    
    // 2. Time scoring (closer to preferred time)
    const rideHour = new Date(ride.dateTime).getHours();
    const preferredHour = 9; // Default preferred time
    const hourDiff = Math.abs(rideHour - preferredHour);
    score += Math.max(0, 50 - (hourDiff * 10));
    
    // 3. Driver rating scoring
    score += user.rating.average * 20;
    
    // 4. Instant booking bonus
    if (ride.instantBook) score += 30;
    
    // 5. Vehicle type preference
    if (ride.vehicle.includes('suv') || ride.vehicle.includes('innova')) score += 20;
    
    // 6. Amenities matching
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

// Serve frontend
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend/index5.html'));
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
        
        // Generate OTP
        const otp = generateOTP();
        const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes
        
        // Save OTP to database
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
        
        // Send OTP via SMS
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
        
        // Find OTP record
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
        
        // Mark OTP as verified
        otpRecord.verified = true;
        await otpRecord.save();
        
        // Find or create user
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
        
        // Generate JWT token
        const token = generateToken(user._id);
        
        // Get profile completion status
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

// ===== USER PROFILE ROUTES =====

// Get user profile
app.get('/api/user/profile', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user._id)
            .select('-otp -__v');
        
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
        
        // Remove restricted fields
        delete updates._id;
        delete updates.phone;
        delete updates.wallet;
        delete updates.rides;
        delete updates.rating;
        delete updates.createdAt;
        
        // Update user
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
            // In production, integrate with Aadhaar verification API
            updates.aadhaarVerified = true;
        }
        
        if (address) {
            updates.address = {
                ...address,
                verified: true // Mock verification
            };
        }
        
        if (vehicle && req.user.role === 'driver') {
            updates.vehicle = {
                ...vehicle,
                verified: true // Mock verification
            };
        }
        
        const user = await User.findByIdAndUpdate(
            req.user._id,
            { $set: updates },
            { new: true, runValidators: true }
        ).select('-otp -__v');
        
        // Simulate criminal check (in production, integrate with police verification API)
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

// ===== RIDE ROUTES =====

// Search rides
app.get('/api/rides/search', authMiddleware, async (req, res) => {
    try {
        const { from, to, date, passengers, minPrice, maxPrice, preferences } = req.query;
        
        // Build query
        const query = {
            status: 'scheduled',
            'seats.available': { $gte: parseInt(passengers) || 1 }
        };
        
        if (from) {
            query['from.city'] = new RegExp(from, 'i');
        }
        
        if (to) {
            query['to.city'] = new RegExp(to, 'i');
        }
        
        if (date) {
            const searchDate = new Date(date);
            const nextDay = new Date(searchDate);
            nextDay.setDate(nextDay.getDate() + 1);
            
            query.dateTime = {
                $gte: searchDate,
                $lt: nextDay
            };
        }
        
        if (minPrice || maxPrice) {
            query.price = {};
            if (minPrice) query.price.$gte = parseInt(minPrice);
            if (maxPrice) query.price.$lte = parseInt(maxPrice);
        }
        
        // Preferences filtering
        if (preferences) {
            const pref = JSON.parse(preferences);
            Object.keys(pref).forEach(key => {
                if (pref[key] === true) {
                    query[`preferences.${key}`] = true;
                }
            });
        }
        
        // Get rides with driver details
        const rides = await Ride.find(query)
            .populate('driver', 'name profilePhoto rating.average vehicle aadhaarVerified criminalCheck.verified')
            .sort({ dateTime: 1, aiRecommendationScore: -1 })
            .limit(50);
        
        // Calculate AI scores
        const ridesWithScore = await Promise.all(rides.map(async (ride) => {
            const aiScore = calculateAIScore(ride, ride.driver);
            ride.aiRecommendationScore = aiScore;
            await ride.save();
            return ride;
        }));
        
        // Sort by AI score
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
        
        // Create new ride
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
        
        // Calculate initial AI score
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

// Get user's rides (as driver or passenger)
app.get('/api/user/rides', authMiddleware, async (req, res) => {
    try {
        const { type = 'upcoming', role = 'all' } = req.query;
        const user = req.user;
        
        let rides = [];
        
        if (role === 'driver' || role === 'all') {
            const driverQuery = { driver: user._id };
            
            if (type === 'upcoming') {
                driverQuery.dateTime = { $gte: new Date() };
                driverQuery.status = 'scheduled';
            } else if (type === 'past') {
                driverQuery.dateTime = { $lt: new Date() };
                driverQuery.status = 'completed';
            }
            
            const driverRides = await Ride.find(driverQuery)
                .populate('passengers.user', 'name profilePhoto')
                .sort({ dateTime: type === 'upcoming' ? 1 : -1 });
            
            rides = [...rides, ...driverRides.map(r => ({ ...r.toObject(), userRole: 'driver' }))];
        }
        
        if (role === 'passenger' || role === 'all') {
            const passengerRides = await Ride.find({
                'passengers.user': user._id,
                'passengers.status': type === 'upcoming' ? 'booked' : 'completed'
            })
            .populate('driver', 'name profilePhoto vehicle')
            .sort({ dateTime: type === 'upcoming' ? 1 : -1 });
            
            rides = [...rides, ...passengerRides.map(r => ({ ...r.toObject(), userRole: 'passenger' }))];
        }
        
        // Sort by date
        rides.sort((a, b) => {
            if (type === 'upcoming') {
                return new Date(a.dateTime) - new Date(b.dateTime);
            } else {
                return new Date(b.dateTime) - new Date(a.dateTime);
            }
        });
        
        res.status(200).json({
            success: true,
            count: rides.length,
            rides
        });
    } catch (error) {
        console.error('Get user rides error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
});

// ===== BOOKING ROUTES =====

// Book a ride
app.post('/api/bookings/book', authMiddleware, profileGateMiddleware, async (req, res) => {
    try {
        const { rideId, seats } = req.body;
        const user = req.user;
        
        // Check if user has enough wallet balance
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
        
        // Deduct from passenger's wallet
        user.wallet.balance -= totalAmount;
        user.wallet.transactions.push({
            amount: totalAmount,
            type: 'debit',
            description: `Booking for ride from ${ride.from.city} to ${ride.to.city}`,
            reference: `BOOK-${Date.now()}`,
            status: 'completed'
        });
        
        // Add to driver's wallet (pending)
        const driver = await User.findById(ride.driver);
        driver.wallet.balance += totalAmount;
        driver.wallet.transactions.push({
            amount: totalAmount,
            type: 'credit',
            description: `Payment for ride booking from ${user.name}`,
            reference: `BOOK-${Date.now()}`,
            status: 'pending' // Will be completed after ride completion
        });
        
        // Update ride
        ride.seats.available -= seats;
        ride.passengers.push({
            user: user._id,
            bookedAt: new Date(),
            status: 'booked',
            paymentStatus: 'paid'
        });
        
        // Create booking record
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
        
        // Save everything
        await Promise.all([
            user.save(),
            driver.save(),
            ride.save(),
            booking.save()
        ]);
        
        // Update user ride count
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

// Cancel booking
app.post('/api/bookings/:id/cancel', authMiddleware, async (req, res) => {
    try {
        const { reason } = req.body;
        const booking = await Booking.findById(req.params.id)
            .populate('ride')
            .populate('passenger');
        
        if (!booking) {
            return res.status(404).json({
                success: false,
                message: 'Booking not found'
            });
        }
        
        if (booking.passenger._id.toString() !== req.user._id.toString()) {
            return res.status(403).json({
                success: false,
                message: 'Not authorized to cancel this booking'
            });
        }
        
        if (booking.status !== 'confirmed') {
            return res.status(400).json({
                success: false,
                message: 'Booking cannot be cancelled'
            });
        }
        
        // Check cancellation time (24 hours before ride)
        const rideTime = new Date(booking.ride.dateTime);
        const now = new Date();
        const hoursBeforeRide = (rideTime - now) / (1000 * 60 * 60);
        
        let refundAmount = 0;
        let cancellationFee = 0;
        
        if (hoursBeforeRide > 24) {
            // Full refund
            refundAmount = booking.totalAmount;
        } else if (hoursBeforeRide > 12) {
            // 50% refund
            refundAmount = booking.totalAmount * 0.5;
            cancellationFee = booking.totalAmount * 0.5;
        } else if (hoursBeforeRide > 6) {
            // 25% refund
            refundAmount = booking.totalAmount * 0.25;
            cancellationFee = booking.totalAmount * 0.75;
        } else {
            // No refund
            cancellationFee = booking.totalAmount;
        }
        
        // Process refund if any
        if (refundAmount > 0) {
            const passenger = await User.findById(booking.passenger._id);
            passenger.wallet.balance += refundAmount;
            passenger.wallet.transactions.push({
                amount: refundAmount,
                type: 'credit',
                description: `Refund for cancelled booking`,
                reference: `REF-${Date.now()}`,
                status: 'completed'
            });
            await passenger.save();
        }
        
        // Update booking
        booking.status = 'cancelled';
        booking.cancellationReason = reason;
        booking.payment.status = 'refunded';
        await booking.save();
        
        // Update ride seats
        const ride = await Ride.findById(booking.ride._id);
        ride.seats.available += booking.seats;
        
        // Remove passenger from ride
        const passengerIndex = ride.passengers.findIndex(
            p => p.user.toString() === booking.passenger._id.toString()
        );
        if (passengerIndex > -1) {
            ride.passengers[passengerIndex].status = 'cancelled';
        }
        
        await ride.save();
        
        res.status(200).json({
            success: true,
            message: 'Booking cancelled successfully',
            refundAmount,
            cancellationFee
        });
    } catch (error) {
        console.error('Cancel booking error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
});

// ===== WALLET ROUTES =====

// Get wallet details
app.get('/api/wallet', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user._id)
            .select('wallet premium.isPremium');
        
        res.status(200).json({
            success: true,
            wallet: {
                balance: user.wallet.balance,
                isPremium: user.premium.isPremium,
                transactions: user.wallet.transactions.slice(-20).reverse() // Last 20 transactions
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
        
        // In production, integrate with payment gateway
        // This is a mock implementation
        
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

// Request withdrawal
app.post('/api/wallet/withdraw', authMiddleware, profileGateMiddleware, async (req, res) => {
    try {
        const { amount, bankDetails } = req.body;
        const user = req.user;
        
        if (!amount || amount < 100) {
            return res.status(400).json({
                success: false,
                message: 'Minimum withdrawal amount is ₹100'
            });
        }
        
        if (amount > user.wallet.balance) {
            return res.status(400).json({
                success: false,
                message: 'Insufficient balance'
            });
        }
        
        // Check if user has any pending withdrawals
        const pendingWithdrawal = await Withdrawal.findOne({
            user: user._id,
            status: 'pending'
        });
        
        if (pendingWithdrawal) {
            return res.status(400).json({
                success: false,
                message: 'You already have a pending withdrawal request'
            });
        }
        
        // Create withdrawal request
        const withdrawal = new Withdrawal({
            user: user._id,
            amount,
            bankDetails,
            status: 'pending'
        });
        
        await withdrawal.save();
        
        // Deduct from wallet (will be reversed if rejected)
        user.wallet.balance -= amount;
        user.wallet.transactions.push({
            amount,
            type: 'debit',
            description: 'Withdrawal request (pending approval)',
            reference: `WDR-${withdrawal._id}`,
            status: 'pending'
        });
        
        await user.save();
        
        res.status(201).json({
            success: true,
            message: 'Withdrawal request submitted. Requires admin approval.',
            withdrawal
        });
    } catch (error) {
        console.error('Withdraw error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
});

// ===== AI RECOMMENDATIONS =====

// Get AI recommendations for user
app.get('/api/ai/recommendations', authMiddleware, async (req, res) => {
    try {
        const user = req.user;
        
        // Get user's frequent routes
        const userBookings = await Booking.find({ passenger: user._id })
            .populate('ride')
            .sort({ createdAt: -1 })
            .limit(10);
        
        const frequentRoutes = {};
        userBookings.forEach(booking => {
            const route = `${booking.ride.from.city}-${booking.ride.to.city}`;
            frequentRoutes[route] = (frequentRoutes[route] || 0) + 1;
        });
        
        // Get popular routes in user's city
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
        
        // Get personalized recommendations based on preferences
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

// ===== PREMIUM FEATURES =====

// Check premium eligibility
app.get('/api/premium/eligibility', authMiddleware, async (req, res) => {
    try {
        const user = req.user;
        
        const eligibility = {
            requiredRides: 500,
            completedRides: user.rides.completed,
            progress: Math.min((user.rides.completed / 500) * 100, 100),
            isEligible: user.rides.completed >= 500,
            benefits: [
                'Higher visibility in search results',
                'Priority listing',
                'Lower commission (5% vs 15%)',
                'Premium badge for trust',
                'Priority customer support',
                'Instant payouts'
            ]
        };
        
        res.status(200).json({
            success: true,
            eligibility
        });
    } catch (error) {
        console.error('Premium eligibility error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
});

// Purchase premium
app.post('/api/premium/purchase', authMiddleware, async (req, res) => {
    try {
        const user = req.user;
        
        if (user.rides.completed < 500) {
            return res.status(400).json({
                success: false,
                message: 'Need 500 completed rides to purchase premium'
            });
        }
        
        const premiumPrice = 299; // Monthly price
        
        if (user.wallet.balance < premiumPrice) {
            return res.status(400).json({
                success: false,
                message: 'Insufficient balance to purchase premium'
            });
        }
        
        // Deduct amount
        user.wallet.balance -= premiumPrice;
        user.wallet.transactions.push({
            amount: premiumPrice,
            type: 'debit',
            description: 'Premium subscription purchase',
            reference: `PREMIUM-${Date.now()}`,
            status: 'completed'
        });
        
        // Activate premium
        const expiresAt = new Date();
        expiresAt.setMonth(expiresAt.getMonth() + 1);
        
        user.premium = {
            isPremium: true,
            purchasedAt: new Date(),
            expiresAt,
            plan: 'monthly'
        };
        
        await user.save();
        
        res.status(200).json({
            success: true,
            message: 'Premium activated successfully',
            premium: user.premium
        });
    } catch (error) {
        console.error('Purchase premium error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
});

// ===== DASHBOARD STATS =====

// Get dashboard statistics
app.get('/api/dashboard/stats', authMiddleware, async (req, res) => {
    try {
        const user = req.user;
        
        // Recent rides
        const recentRides = await Ride.find({
            $or: [
                { driver: user._id },
                { 'passengers.user': user._id }
            ],
            dateTime: { $gte: new Date() }
        })
        .populate('driver', 'name profilePhoto')
        .sort({ dateTime: 1 })
        .limit(5);
        
        // Earnings stats
        const earningsStats = await Booking.aggregate([
            {
                $match: {
                    $or: [
                        { passenger: user._id },
                        { 'ride.driver': user._id }
                    ],
                    status: 'completed',
                    createdAt: {
                        $gte: new Date(new Date().getFullYear(), new Date().getMonth(), 1)
                    }
                }
            },
            {
                $lookup: {
                    from: 'rides',
                    localField: 'ride',
                    foreignField: '_id',
                    as: 'ride'
                }
            },
            {
                $unwind: '$ride'
            },
            {
                $group: {
                    _id: null,
                    totalSpent: {
                        $sum: {
                            $cond: [{ $eq: ['$passenger', user._id] }, '$totalAmount', 0]
                        }
                    },
                    totalEarned: {
                        $sum: {
                            $cond: [{ $eq: ['$ride.driver', user._id] }, '$totalAmount', 0]
                        }
                    }
                }
            }
        ]);
        
        // Popular routes for user
        const popularRoutes = await Booking.aggregate([
            {
                $match: {
                    passenger: user._id,
                    status: 'completed'
                }
            },
            {
                $lookup: {
                    from: 'rides',
                    localField: 'ride',
                    foreignField: '_id',
                    as: 'ride'
                }
            },
            {
                $unwind: '$ride'
            },
            {
                $group: {
                    _id: {
                        from: '$ride.from.city',
                        to: '$ride.to.city'
                    },
                    count: { $sum: 1 }
                }
            },
            { $sort: { count: -1 } },
            { $limit: 3 }
        ]);
        
        const stats = {
            user: {
                name: user.name,
                role: user.role,
                rating: user.rating.average,
                ridesCompleted: user.rides.completed,
                walletBalance: user.wallet.balance,
                isPremium: user.premium.isPremium
            },
            recentRides,
            earnings: earningsStats[0] || { totalSpent: 0, totalEarned: 0 },
            popularRoutes: popularRoutes.map(r => ({
                from: r._id.from,
                to: r._id.to,
                frequency: r.count
            }))
        };
        
        res.status(200).json({
            success: true,
            stats
        });
    } catch (error) {
        console.error('Dashboard stats error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
});

// ===== ADMIN ROUTES =====

// Admin middleware
const adminMiddleware = async (req, res, next) => {
    try {
        // Check if user is admin (in production, use proper admin check)
        // This is a mock implementation
        if (req.user.phone !== '9999999999') {
            return res.status(403).json({
                success: false,
                message: 'Access denied. Admin only.'
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

// Get all users (admin)
app.get('/api/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const users = await User.find()
            .select('-otp -__v')
            .sort({ createdAt: -1 });
        
        res.status(200).json({
            success: true,
            count: users.length,
            users
        });
    } catch (error) {
        console.error('Get users error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
});

// Get withdrawal requests (admin)
app.get('/api/admin/withdrawals', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const { status } = req.query;
        
        const query = {};
        if (status) query.status = status;
        
        const withdrawals = await Withdrawal.find(query)
            .populate('user', 'name phone')
            .sort({ createdAt: -1 });
        
        res.status(200).json({
            success: true,
            count: withdrawals.length,
            withdrawals
        });
    } catch (error) {
        console.error('Get withdrawals error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
});

// Process withdrawal (admin)
app.post('/api/admin/withdrawals/:id/process', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const { action, notes } = req.body;
        const withdrawal = await Withdrawal.findById(req.params.id)
            .populate('user');
        
        if (!withdrawal) {
            return res.status(404).json({
                success: false,
                message: 'Withdrawal not found'
            });
        }
        
        if (withdrawal.status !== 'pending') {
            return res.status(400).json({
                success: false,
                message: 'Withdrawal already processed'
            });
        }
        
        if (action === 'approve') {
            withdrawal.status = 'approved';
            withdrawal.adminNotes = notes;
            withdrawal.processedAt = new Date();
            
            // Update user's transaction status
            const user = withdrawal.user;
            const transaction = user.wallet.transactions.find(
                t => t.reference === `WDR-${withdrawal._id}`
            );
            
            if (transaction) {
                transaction.status = 'completed';
                transaction.description = 'Withdrawal processed';
            }
            
            await user.save();
        } else if (action === 'reject') {
            withdrawal.status = 'rejected';
            withdrawal.rejectionReason = notes;
            
            // Refund amount to user's wallet
            const user = withdrawal.user;
            user.wallet.balance += withdrawal.amount;
            
            const transaction = user.wallet.transactions.find(
                t => t.reference === `WDR-${withdrawal._id}`
            );
            
            if (transaction) {
                transaction.status = 'failed';
                transaction.description = 'Withdrawal rejected';
            }
            
            user.wallet.transactions.push({
                amount: withdrawal.amount,
                type: 'credit',
                description: 'Refund for rejected withdrawal',
                reference: `REF-${Date.now()}`,
                status: 'completed'
            });
            
            await user.save();
        }
        
        await withdrawal.save();
        
        res.status(200).json({
            success: true,
            message: `Withdrawal ${action}d successfully`,
            withdrawal
        });
    } catch (error) {
        console.error('Process withdrawal error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
});

// ===== HEALTH CHECK =====

app.get('/api/health', (req, res) => {
    res.status(200).json({
        success: true,
        message: 'RideShare Backend is running',
        timestamp: new Date(),
        uptime: process.uptime(),
        database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
    });
});

// ===== 404 HANDLER =====

app.use('*', (req, res) => {
    res.status(404).json({
        success: false,
        message: 'Route not found'
    });
});

// ===== ERROR HANDLER =====

app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    
    res.status(err.status || 500).json({
        success: false,
        message: err.message || 'Internal server error',
        ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
    });
});

// ===== START SERVER WITH PROPER DB CONNECTION =====

const startServer = async () => {
    try {
        // ✅ FIX 1: Clean MongoDB connection without deprecated options
        await mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/rideshare');
        console.log('✅ MongoDB Connected Successfully');

        const server = app.listen(PORT, () => {
            console.log(`🚀 RideShare Backend running on port ${PORT}`);
            console.log(`🔗 Health check: http://localhost:${PORT}/api/health`);
            console.log(`🌐 Frontend: http://localhost:${PORT}`);
            console.log(`📊 MongoDB: Connected`);
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
