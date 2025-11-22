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
const crypto = require('crypto');

// Models
const User = require('./models/User');
const Appointment = require('./models/Appointment');
const Schedule = require('./models/Schedule');

const app = express();

// Security
app.use(helmet({ contentSecurityPolicy: false }));
app.use(rateLimit({ windowMs: 10 * 60 * 1000, max: 200 }));
app.use(hpp());
app.use(mongoSanitize());
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// DB
mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/ulr')
    .then(() => console.log('MongoDB Connected'))
    .catch(err => console.log(err));

// Helpers
const generateSlug = (name) => {
    const clean = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)+/g, '');
    const suffix = crypto.randomBytes(2).toString('hex');
    return `${clean}-${suffix}`;
};

// Auth Middleware
const protect = async (req, res, next) => {
    let token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ msg: 'Not authorized' });
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = await User.findById(decoded.id);
        next();
    } catch (err) { res.status(401).json({ msg: 'Token failed' }); }
};

// --- ROUTES ---

// 1. Register (User Name + Schedule Name)
app.post('/api/auth/register', async (req, res) => {
    // We now accept 'name' (User) AND 'scheduleName' (Schedule)
    const { name, scheduleName, email, password } = req.body;
    try {
        if (await User.findOne({ email })) return res.status(400).json({ msg: 'User exists' });

        // Create User with Real Name
        const user = await User.create({ name, email, password, handle: 'legacy' });
        
        // Generate Slug and Create First Schedule
        const slug = generateSlug(scheduleName);
        await Schedule.create({ userId: user._id, name: scheduleName, slug });

        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '30d' });
        res.status(201).json({ token, user: { id: user._id, name: user.name } });
    } catch (err) {
        console.error(err);
        res.status(500).json({ msg: 'Server error' });
    }
});

// 2. Login
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user || !(await user.matchPassword(password))) return res.status(400).json({ msg: 'Invalid credentials' });

        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '30d' });
        res.json({ token, user: { id: user._id, name: user.name } });
    } catch (err) { res.status(500).json({ msg: 'Server error' }); }
});

// 3. Get Dashboard Data
app.get('/api/dashboard', protect, async (req, res) => {
    try {
        const schedules = await Schedule.find({ userId: req.user._id });
        const appointments = await Appointment.find({ providerId: req.user._id })
            .populate('scheduleId', 'name')
            .sort({ startTime: 1 });
        res.json({ schedules, appointments });
    } catch (err) { res.status(500).json({ msg: 'Error fetching data' }); }
});

// 4. Create New Schedule Link
app.post('/api/schedules', protect, async (req, res) => {
    try {
        const slug = generateSlug(req.body.name);
        const schedule = await Schedule.create({
            userId: req.user._id,
            name: req.body.name,
            slug
        });
        res.json(schedule);
    } catch (err) { res.status(500).json({ msg: 'Error creating schedule' }); }
});

// 5. Public Schedule Lookup
app.get('/api/p/:slug', async (req, res) => {
    try {
        const schedule = await Schedule.findOne({ slug: req.params.slug }).populate('userId', 'name');
        if (!schedule) return res.status(404).json({ msg: 'Schedule not found' });
        
        const appointments = await Appointment.find({ 
            providerId: schedule.userId._id, 
            startTime: { $gte: new Date() } 
        });

        res.json({ schedule, provider: schedule.userId, busySlots: appointments });
    } catch (err) { res.status(500).json({ msg: 'Server error' }); }
});

// 6. Create Appointment
app.post('/api/appointments', async (req, res) => {
    const { scheduleId, providerId, customerName, customerEmail, startTime, notes } = req.body;
    try {
        const appointment = await Appointment.create({
            scheduleId,
            providerId,
            customerName,
            customerEmail,
            startTime,
            notes
        });
        res.status(201).json(appointment);
    } catch (err) { res.status(500).json({ msg: 'Error booking' }); }
});

// 7. AI Optimization
app.post('/api/optimize', protect, async (req, res) => {
    if (!process.env.DEEPSEEK_API_KEY) return res.json({ suggestion: "AI Key missing." });
    
    try {
        const appointments = await Appointment.find({ 
            providerId: req.user._id,
            startTime: { $gte: new Date() } 
        });
        
        const scheduleData = appointments.map(a => `${a.startTime}`).join('\n');
        const response = await axios.post('https://api.deepseek.com/chat/completions', {
            model: "deepseek-chat", 
            messages: [
                { role: "system", content: "Analyze schedule dates." },
                { role: "user", content: `Suggest a 1-hour focus block for: ${scheduleData}. Return JSON { "date": "YYYY-MM-DD", "time": "HH:MM", "reason": "..." }` }
            ]
        }, { headers: { 'Authorization': `Bearer ${process.env.DEEPSEEK_API_KEY}` }});

        res.json({ suggestion: response.data.choices[0].message.content });
    } catch (err) { res.json({ suggestion: "Optimization unavailable." }); }
});

app.get('*', (req, res) => res.sendFile(path.resolve(__dirname, 'public', 'index.html')));

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));