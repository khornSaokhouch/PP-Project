const User = require('../models/userModel');
const jwt = require('jsonwebtoken');

// Get User Profile
const getProfile = async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];  // Bearer token

  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }

  try {
    // Verify JWT token
    const decoded = jwt.verify(token, 'your_jwt_secret_key');  // Use the same secret key as during login

    // Find the user by ID from the token
    const user = await User.findById(decoded.userId).select('-password');  // Exclude password

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.status(200).json({ user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
};

module.exports = { getProfile };
