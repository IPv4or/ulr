const mongoose = require('mongoose');

const AppointmentSchema = new mongoose.Schema({
    providerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    customerName: { type: String, required: true },
    customerEmail: { type: String, required: true },
    startTime: { type: Date, required: true },
    duration: { type: Number, default: 30 }, 
    notes: { type: String },
    createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Appointment', AppointmentSchema);