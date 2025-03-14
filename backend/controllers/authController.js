const bcrypt = require("bcryptjs");
const User = require("../models/userModel");
require("dotenv").config(); // Ensure environment variables are loaded

// Register User
const register = async (req, res) => {
  try {
    const { fullName, email, password, adminId, status: requestedStatus, role: requestedRole } = req.body;

    // Define allowed roles and statuses (MUST match your userModel.js schema)
    const allowedRoles = ["admin", "user"];
    const allowedStatuses = ["active", "banned"];

    // Validate role and status (default if invalid)
    const role = allowedRoles.includes(requestedRole) ? requestedRole : "user";
    const status = allowedStatuses.includes(requestedStatus) ? requestedStatus : "active";

    // Validate required fields
    if (!fullName || !email || !password) {
      return res.status(400).json({
        success: false,
        message: "fullName, email, and password are required.",
      });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: "User with this email already exists.",
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);


    // Validate adminId if provided
    let admin = null;
    if (adminId) {
      admin = await User.findOne({ _id: adminId, role: "admin" });
      if (!admin) {
        return res.status(404).json({
          success: false,
          message: "Admin not found. Check the provided admin ID.",
        });
      }
    }

    // Create new user
    const newUser = new User({
      fullName,
      email,
      password: hashedPassword,
      role,
      status,
      adminId: admin ? admin._id : null,
    });

    // Save user to database
    await newUser.save();

    // Success response
    return res.status(201).json({
      success: true,
      message: "User created successfully.",
      user: {
        id: newUser._id,
        fullName: newUser.fullName,
        email: newUser.email,
        role: newUser.role,
        status: newUser.status,
        profile_image: newUser.imageUrl || null,
        joined_date: newUser.createdAt,
      },
    });
  } catch (error) {
    console.error("Error during registration:", error);

    // Handle duplicate key error (MongoDB)
    if (error.code === 11000) {
      return res.status(400).json({
        success: false,
        message: "User with this email already exists.",
      });
    }

    return res.status(500).json({
      success: false,
      message: "An error occurred during signup. Please try again later.",
    });
  }
};

const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Check if user exists
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ success: false, message: "Invalid email or password." });
    }

    console.log("User found:", user);

    // Compare entered password with hashed password
    const isMatch = await bcrypt.compare(password, user.password);

    console.log("Entered Password:", password);
    console.log("Stored Hashed Password:", user.password);
    console.log("Password Match:", isMatch);

    if (!isMatch) {
      return res.status(400).json({ success: false, message: "Invalid email or password." });
    }

    // Generate JWT token
    const token = jwt.sign({ userId: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: "1d" });

    res.status(200).json({ success: true, message: "Login successful.", token });
  } catch (error) {
    console.error("Error during login:", error);
    res.status(500).json({ success: false, message: "An error occurred during login." });
  }
};

const checkAuth = async (req, res) => {
  try {
    // Ensure userId exists in request (middleware should set this)
    if (!req.userId) {
      return res.status(401).json({ success: false, message: "Unauthorized" });
    }

    // Find user and exclude password from response
    const user = await User.findById(req.userId).lean();
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    // Remove password from response manually
    delete user.password;

    return res.status(200).json({ success: true, user });
  } catch (error) {
    console.error("Error checking auth:", error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
};







module.exports = { register, login, checkAuth };




// Login User
// const login = async (req, res) => {
//   const { email, password } = req.body;

//   // Validate email and password are provided
//   if (!email || !password) {
//     return res.status(400).json({ success: false, message: "Email and password are required." });
//   }

//   try {
//     // Find the user by email
//     const user = await User.findOne({ email });

//     // Debugging: Check if user is found
//     console.log("User found: ", user);

//     // Check if user exists
//     if (!user) {
//       return res.status(400).json({ success: false, message: "Invalid email or password." });
//     }

//     // Compare the provided password with the stored hashed password
//     const isMatch = await bcrypt.compare(password, user.password);

//     // Debugging: Check password comparison result
//     console.log("Password match status: ", isMatch);

//     if (!isMatch) {
//       return res.status(400).json({ success: false, message: "Invalid email or password." });
//     }

//     // Proceed with creating a JWT token if passwords match
//     const token = jwt.sign(
//       { userId: user._id, email: user.email, fullName: user.fullName },
//       process.env.JWT_SECRET, // Ensure you have a JWT secret key in your environment variables
//       { expiresIn: '1h' } // Token expires in 1 hour
//     );

//     // Respond with user info and token
//     res.status(200).json({
//       success: true,
//       message: "Login successful.",
//       token,
//       user: {
//         id: user._id,
//         fullName: user.fullName,
//         email: user.email,
//         role: user.role,
//         status: user.status
//       }
//     });

//   } catch (err) {
//     // Log error for debugging
//     console.error("Login error:", err);  
//     res.status(500).json({ success: false, message: "An error occurred during login." });
//   }
// };

// // Send reset password email
// const forgotPassword = async (req, res) => {
//   try {
//     const { email } = req.body;

//     // Check if user exists
//     const user = await User.findOne({ email });
//     if (!user) {
//       return res.status(400).json({ success: false, message: "Email not found." });
//     }

//     // Generate a password reset token (random bytes converted to hex)
//     const resetToken = crypto.randomBytes(32).toString("hex");

//     // Hash the reset token and store it in the user record
//     user.resetPasswordToken = crypto.createHash("sha256").update(resetToken).digest("hex");
//     user.resetPasswordExpire = Date.now() + 10 * 60 * 1000; // Token expires in 10 minutes
//     await user.save();

//     // Create reset URL (frontend should handle the token)
//     const resetUrl = `http://localhost:3000/reset-password/${resetToken}`;

//     // Send email (You need to configure SMTP)
//     const transporter = nodemailer.createTransport({
//       service: "gmail",
//       auth: {
//         user: process.env.EMAIL_USER,
//         pass: process.env.EMAIL_PASS,
//       },
//     });

//     await transporter.sendMail({
//       from: process.env.EMAIL_USER,
//       to: user.email,
//       subject: "Password Reset Request",
//       html: `<p>Click <a href="${resetUrl}">here</a> to reset your password.</p>`,
//     });

//     res.status(200).json({ success: true, message: "Password reset link sent to email." });
//   } catch (error) {
//     console.error("Forgot Password Error:", error);
//     res.status(500).json({ success: false, message: "Something went wrong." });
//   }
// };

// // Reset Password Controller
// const resetPassword = async (req, res) => {
//   try {
//     const { token } = req.params;
//     const { newPassword } = req.body;

//     // Hash the token to compare with the stored hashed token
//     const hashedToken = crypto.createHash("sha256").update(token).digest("hex");

//     // Find user by reset token and check expiration
//     const user = await User.findOne({
//       resetPasswordToken: hashedToken,
//       resetPasswordExpire: { $gt: Date.now() },
//     });

//     if (!user) {
//       return res.status(400).json({ success: false, message: "Invalid or expired token." });
//     }

//     // Hash the new password
//     const salt = await bcrypt.genSalt(10);
//     user.password = await bcrypt.hash(newPassword, salt);

//     // Clear reset token fields
//     user.resetPasswordToken = undefined;
//     user.resetPasswordExpire = undefined;

//     // Save user with new password
//     await user.save();

//     res.status(200).json({ success: true, message: "Password reset successful. You can now log in." });
//   } catch (error) {
//     console.error("Reset Password Error:", error);
//     res.status(500).json({ success: false, message: "Something went wrong." });
//   }
// };

// // Logout Function
// const logout = async (req, res) => {
//   try {
//     const token = req.header("Authorization")?.split(" ")[1]; // Extract Bearer Token

//     if (!token) {
//       return res.status(400).json({ success: false, message: "No token provided." });
//     }

//     // Decode token to get expiration time
//     const decoded = jwt.verify(token, process.env.JWT_SECRET);

//     // Store the token in Redis blacklist with an expiration time
//     await redisClient.setEx(token, decoded.exp - Math.floor(Date.now() / 1000), "blacklisted");

//     res.status(200).json({ success: true, message: "Logout successful." });
//   } catch (error) {
//     console.error("Logout error:", error);
//     res.status(500).json({ success: false, message: "An error occurred during logout." });
//   }
// };

// const checkAuth = async (req, res) => {
//   try {
//     if (!req.userId) {
//       return res.status(401).json({ success: false, message: "Unauthorized access" });
//     }

//     const user = await User.findById(req.userId).select("-password"); // Exclude password

//     if (!user) {
//       return res.status(404).json({ success: false, message: "User not found" });
//     }

//     res.status(200).json({ success: true, user });
//   } catch (error) {
//     console.error("Error checking auth:", error);
//     res.status(500).json({ success: false, message: "Internal server error" });
//   }
// };

