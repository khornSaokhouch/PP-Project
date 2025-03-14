const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const authRoutes = require('./routes/auth'); 
const { connectToDatabase } = require('./database/mongoosedb');

// Load environment variables
dotenv.config();

const app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());

// Connect to MongoDB
connectToDatabase().then(() => {
    console.log("✅ Successfully connected to MongoDB");
}).catch((error) => {
    console.error("❌ Error connecting to MongoDB:", error);
    process.exit(1); // Exit process if DB connection fails
});

// Authentication Routes
app.use("/api/auth", authRoutes);

// Handle Undefined Routes (404)
app.use((req, res, next) => {
    res.status(404).json({ error: "Route not found" });
});

// Global Error Handling Middleware
app.use((err, req, res, next) => {
    console.error("🚨 Error:", err.message);
    res.status(500).json({ error: 'Something went wrong, please try again later.' });
});

// Start Server
app.listen(port, () => {
    console.log(`🚀 Server running on http://localhost:${port}`);
});
