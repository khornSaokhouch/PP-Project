const express = require('express');
const { register, login, checkAuth } = require('../controllers/authController.js');
const { getProfile } = require('../controllers/userController.js');

const router = express.Router();

// Route for user registration
router.post('/register', register);

// Route for user login
router.post('/login', login);

// // Route for getting user profile (using GET)
// router.get('/getProfile', getProfile);
// router.post('/logout', logout);

router.get("/check-auth", checkAuth);

module.exports = router;

