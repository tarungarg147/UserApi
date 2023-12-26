const express = require("express");
const router = express.Router();
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const Register = require("../models/register.js");
const jwt = require('jsonwebtoken')

// Function to validate email format
function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

// Function to validate password format
function isValidPassword(password) {
    // Password  contain special character
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/;
    return passwordRegex.test(password);
}

// Signup (Register) API
router.post("/signup", async (req, res) => {
    const email = req.body.email;
    const password = req.body.password;
    const confirmPassword = req.body.confirmPassword;
    const name = req.body.name;
    const image = req.body.image;

    // Validate email format
    if (!isValidEmail(email)) {
        return res.status(400).json({
            message: "Invalid email address format",
        });
    }

    // Validate password format
    if (!isValidPassword(password)) {
        return res.status(400).json({
            message: "Invalid password format",
        });
    }

    // Confirm password matches
    if (password !== confirmPassword) {
        return res.status(400).json({
            message: "Password not matched!",
        });
    }

    // Hash the password
    bcrypt.hash(password, 10, async (err, hash) => {
        if (err) {
            return res.status(500).json({
                message: "Something went wrong",
            });
        }

        // Generate a verification code and expiration time
        const verificationCode = crypto.randomBytes(3).toString('hex');
        const verificationCodeExpiration = Date.now() + 300000; // 5 minutes

        // Save user details in the database with the verification code and expiration time
        const registerDetails = new Register({
            email: email,
            password: hash,
            name: name,
            image: image,
            verificationCode: verificationCode,
            verificationCodeExpiration: verificationCodeExpiration,
            isVerified: false,
        });

        try {
            const savedUser = await registerDetails.save();

            // Send verification email with code
            await sendVerificationEmail(savedUser.email, verificationCode, password);

            res.status(201).json({
                message: "User inserted successfully. Check your email for verification.",
                results: savedUser,
            });
        } catch (err) {
            res.status(500).json({
                error: err,
            });
        }
    });
});

// Helper function to send verification email
async function sendVerificationEmail(email, verificationCode, password) {
    
    // Use nodemaile for email
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASSWORD,
        },
    });

    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Email Verification',
        text: `Your verification code is: ${verificationCode}`,
    };

    try {
        const info = await transporter.sendMail(mailOptions);
        console.log('Email sent:', info.response);
    } catch (error) {
        console.error('Error sending email:', error);
        throw error;
    }
}

// login Api

router.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;

        // Validate email format
        if (!isValidEmail(email)) {
            return res.status(400).json({
                message: "Invalid email address format",
            });
        }

        // Validate password format
        if (!isValidPassword(password)) {
            return res.status(400).json({
                message: "Invalid password format",
            });
        }

        const user = await Register.findOne({ email });

        if (!user) {
            return res.status(404).json({
                message: "Email not registered",
            });
        }

        if (!user.isVerified) {
            return res.status(401).json({
                message: "Email not verified",
            });
        }

        bcrypt.compare(password, user.password, (err, result) => {
            if (err || !result) {
                return res.status(401).json({
                    message: "Authentication failed",
                });
            }

         // If authentication is successful, generate a JWT token
        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
            expiresIn: '1h', // Token expiration time
        });

        res.status(200).json({
            message: "Login successful",
            user: user,
            token: token,
        });

        });
    } catch (err) {
        console.error(err);
        res.status(500).json({
            error: "Internal server error",
        });
    }
});

//  verify JWT token
const verifyToken = (req, res, next) => {
    const token = req.header('Authorization');

    if (!token) {
        return res.status(401).json({ message: 'Access denied. No token provided.' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(403).json({ message: 'Invalid token.' });
    }
};

// Get user profile
router.get("/profile", verifyToken, async (req, res) => {
    const userId = req.user.userId;

    try {
        const user = await Register.findById(userId);

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        res.status(200).json({
            email: user.email,
            name: user.name,
            image: user.image,
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Update user profile
router.put("/profile", verifyToken, async (req, res) => {
    const userId = req.user.userId;
    const { name, image } = req.body;

    try {
        const user = await Register.findById(userId);

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Update user profile details
        user.name = name || user.name;
        user.image = image || user.image;

        await user.save();

        res.status(200).json({
            message: 'Profile updated successfully',
            email: user.email,
            name: user.name,
            image: user.image,
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
});
// forgot password
router.post('/forgot-password', async (req, res) => {
    const email = req.body.email;

    // Validate email
    if (!isValidEmail(email)) {
        return res.status(400).json({ message: 'Invalid email address format' });
    }

    try {
        const user = await Register.findOne({ email });

        // Check if the user is registered and verified
        if (!user || !user.isVerified) {
            return res.status(404).json({ message: 'Email not registered or verified' });
        }

        const resetToken = crypto.randomBytes(20).toString('hex');
        const resetTokenExpiration = Date.now() + 300000; // 5 minutes

        
        user.resetToken = resetToken;
        user.resetTokenExpiration = resetTokenExpiration;
        await user.save();

        // Send  email with the token
        await sendResetEmail(user.email, resetToken);

        res.status(200).json({ message: 'Reset token sent to your email' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// send reset email
async function sendResetEmail(email, resetToken) {
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASSWORD,
        },
    });

    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Password Reset',
        text: `Use this OTP to reset your password: ${resetToken}`,
    };

    try {
        const info = await transporter.sendMail(mailOptions);
        console.log('Email sent:', info.response);
    } catch (error) {
        console.error('Error sending email:', error);
        throw error;
    }
}

// OTP verification and password update
router.post("/verify-otp", async (req, res) => {
    const { email, otp, newPassword } = req.body;

    try {
        const user = await Register.findOne({ email });

        if (!user) {
            return res.status(404).json({ message: "Email not registered" });
        }

        // Check if the OTP is valid and not expired
        if (user.resetToken !== otp || Date.now() > user.resetTokenExpiration) {
            return res.status(401).json({ message: "Invalid or expired OTP" });
        }

        // Hash the new password and update user's password
        bcrypt.hash(newPassword, 10, async (err, hash) => {
            if (err) {
                return res.status(500).json({ message: "Something went wrong" });
            }

            user.password = hash;
            user.resetToken = undefined;
            user.resetTokenExpiration = undefined;

            await user.save();

            res.status(200).json({ message: "Password updated successfully" });
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Internal server error" });
    }
});

//  send reset email
async function sendResetEmail(email, resetToken) {
    
    // Use nodemailer for email
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASSWORD,
        },
    });

    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Password Reset',
        text: `Use this OTP to reset your password: ${resetToken}`,
    };

    try {
        const info = await transporter.sendMail(mailOptions);
        console.log('Email sent:', info.response);
    } catch (error) {
        console.error('Error sending email:', error);
        throw error;
    }
}



module.exports = router;