const mongoose = require("mongoose");
require("dotenv").config();

const connectToDatabase = async () => {
    console.log("MONGO_URI:", process.env.MONGO_URI); // Debugging line

    if (!process.env.MONGO_URI) {
        console.error("❌ MONGO_URI is missing from .env file");
        process.exit(1);
    }

    try {
        await mongoose.connect(process.env.MONGO_URI); // No deprecated options needed
        console.log("✅ MongoDB connected successfully");
    } catch (error) {
        console.error("❌ MongoDB connection failed:", error);
        process.exit(1);
    }
};

module.exports = { connectToDatabase };

