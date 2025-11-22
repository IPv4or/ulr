require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const hpp = require('hpp');
const mongoSanitize = require('express-mongo-sanitize');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const path = require('path');
const axios = require('axios');

// Models imports
const User = require('./models/User');
const Appointment = require('./models/Appointment');

const app = express();

// --- SECURITY MIDDLEWARE ---

// Set Security Headers
app.use(helmet({
    contentSecurityPolicy: false, // Disabled to allow inline scripts/styles in this SPA structure
}));

// Rate Limiting (100 requests per 10 mins)
const limiter = rateLimit({
    windowMs: 10 * 60 * 1000,
    max: 100,
    message: 'Too many requests from this IP, please try again later.'
});
app.use('/api', limiter);

// Prevent Parameter Pollution
app.use(hpp());

// Data Sanitization against NoSQL query injection
app.use(mongoSanitize());

// CORS
app.use(cors());

// Body Parser
app.use(express.json());

// Serve Static Files (Frontend)
app.use(express.static(path.join(__dirname, 'public')));

// --- DB CONNECTION ---
mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/ulr')
    .then(() => console.log('MongoDB Connected'))
    .catch(err => console.log(err));

// --- AUTH MIDDLEWARE ---
const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }
    
    if (!token) return res.status(401).json({ msg: 'Not authorized' });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = await User.findById(decoded.id);
        next();
    } catch (err) {
        res.status(401).json({ msg: 'Token failed' });
    }
};

// --- ROUTES ---

// 1. Auth: Register
app.post('/api/auth/register', async (req, res) => {
    const { name, email, password, handle } = req.body;
    try {
        let user = await User.findOne({ email });
        if (user) return res.status(400).json({ msg: 'User already exists' });
        
        const handleCheck = await User.findOne({ handle });
        if (handleCheck) return res.status(400).json({ msg: 'Handle taken' });

        user = await User.create({ name, email, password, handle });
        
        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '30d' });
        res.status(201).json({ token, user: { id: user._id, name: user.name, handle: user.handle } });
    } catch (err) {
        res.status(500).json({ msg: 'Server error' });
    }
});

// 2. Auth: Login
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(400).json({ msg: 'Invalid credentials' });

        const isMatch = await user.matchPassword(password);
        if (!isMatch) return res.status(400).json({ msg: 'Invalid credentials' });

        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '30d' });
        res.json({ token, user: { id: user._id, name: user.name, handle: user.handle } });
    } catch (err) {
        res.status(500).json({ msg: 'Server error' });
    }
});

// 3. Public Profile & Availability
app.get('/api/p/:handle', async (req, res) => {
    try {
        const user = await User.findOne({ handle: req.params.handle }).select('-password -email');
        if (!user) return res.status(404).json({ msg: 'Provider not found' });
        
        const appointments = await Appointment.find({ 
            providerId: user._id, 
            startTime: { $gte: new Date() } 
        });

        res.json({ provider: user, busySlots: appointments });
    } catch (err) {
        res.status(500).json({ msg: 'Server error' });
    }
});

// 4. Create Appointment
app.post('/api/appointments', async (req, res) => {
    const { providerId, customerName, customerEmail, startTime, notes } = req.body;
    try {
        const appointment = await Appointment.create({
            providerId,
            customerName,
            customerEmail,
            startTime,
            notes
        });
        res.status(201).json(appointment);
    } catch (err) {
        res.status(500).json({ msg: 'Error booking' });
    }
});

// 5. Dashboard Data (Protected)
app.get('/api/dashboard', protect, async (req, res) => {
    try {
        const appointments = await Appointment.find({ providerId: req.user._id }).sort({ startTime: 1 });
        res.json(appointments);
    } catch (err) {
        res.status(500).json({ msg: 'Error fetching data' });
    }
});

// 6. Invisible AI Optimization (DeepSeek)
app.post('/api/optimize', protect, async (req, res) => {
    try {
        const appointments = await Appointment.find({ 
            providerId: req.user._id,
            startTime: { $gte: new Date() } 
        });

        if (!process.env.DEEPSEEK_API_KEY) {
            return res.json({ suggestion: "AI Optimization requires API Key configuration." });
        }

        const scheduleData = appointments.map(a => `${a.startTime} - ${a.customerName}`).join('\n');
        
        const prompt = `
        Here is a professional's schedule:
        ${scheduleData}
        
        Identify the most cluttered day and suggest a specific 1-hour "Deep Focus Block" that should be marked as busy to prevent burnout. 
        Return ONLY a JSON string like: {"date": "YYYY-MM-DD", "time": "HH:MM", "reason": "High density of meetings"}
        Do not include markdown formatting.
        `;

        const response = await axios.post('https://api.deepseek.com/chat/completions', {
            model: "deepseek-chat", 
            messages: [
                { role: "system", content: "You are a helpful scheduling assistant." },
                { role: "user", content: prompt }
            ]
        }, {
            headers: {
                'Authorization': `Bearer ${process.env.DEEPSEEK_API_KEY}`,
                'Content-Type': 'application/json'
            }
        });

        const aiContent = response.data.choices[0].message.content;
        res.json({ suggestion: aiContent });

    } catch (err) {
        console.error("AI Error:", err.message);
        res.status(500).json({ msg: 'Optimization failed' });
    }
});

// SPA Fallback
app.get('*', (req, res) => {
    res.sendFile(path.resolve(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));