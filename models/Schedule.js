const mongoose = require('mongoose');

const ScheduleSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    name: { type: String, required: true }, // e.g. "Quick Call"
    slug: { type: String, required: true, unique: true }, // e.g. "quick-call-x9s2"
    duration: { type: Number, default: 30 }, // minutes
    createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Schedule', ScheduleSchema);