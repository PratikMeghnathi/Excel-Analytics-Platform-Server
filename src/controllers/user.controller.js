import mongoose from "mongoose";
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken'

import { Analysis, DataSet, FileUpload, User } from "../models/index.js";
import { cookieOptions, createError, errorCodes } from "../utils/index.js";
import { env } from "../config/index.js";

import Redis from 'ioredis';
import Mailjet from "node-mailjet";
import crypto from "crypto";

// Initialize Redis client
const redisClient = new Redis({
    username: env.redis_username,
    password: env.redis_password,
    host: env.redis_host,
    port: env.redis_port,
    maxRetriesPerRequest: null
});
redisClient.on('error', (err) => {
    console.error('Redis connection error:', err);
});
redisClient.on('connect', () => {
    console.log('Connected to Redis');
});

// Initialize Mailjet
const mailjetClient = Mailjet.apiConnect(
    env.mailjet_api_key,
    env.mailjet_secret_key
);

// Email verification token expiry (15 minutes)
const EMAIL_VERIFICATION_EXPIRY = 15 * 60;

const generateVerificationToken = () => {
    return crypto.randomBytes(32).toString('hex');
};

const sendVerificationEmail = async (email, username, verificationToken) => {
    const verification_url = `${env.frontend_url}/verify-email?token=${verificationToken}`;

    const emailData = {
        Messages: [{
            From: {
                Email: env.from_email,
                Name: env.from_name || 'Excel Analytics'
            },
            To: [{
                Email: email,
                Name: username
            }],
            Subject: 'Verify Your Email Address - Excel Analytics',
            "TemplateID": 7034484,
            "TemplateLanguage": true,
            "Subject": "Verify Your Email Address - Excel Analytics",
            "Variables": {
                verification_url,
                username
            }
        }]
    };

    try {
        const result = await mailjetClient.post('send', { version: 'v3.1' }).request(emailData);
        console.log('Verification email sent successfully:', result.body);
        return { success: true };
    } catch (error) {
        console.error('Error sending verification email:', error);
        return { success: false, error: error.message };
    }
};

// Store verification token in Redis
const storeVerificationToken = async (token, userData) => {
    try {
        const key = `email_verification:${token}`;
        await redisClient.setex(key, EMAIL_VERIFICATION_EXPIRY, JSON.stringify(userData));
        return { success: true };
    } catch (error) {
        console.error('Error storing verification token:', error);
        return { success: false, error: error.message };
    }
};

// Register user with email verification
export const registerUser = async (req, res) => {
    try {
        const { username, email, password } = req.body;

        if (!username || !email || !password) {
            return res.status(400).json(createError(errorCodes.badRequest, 'input', 'Please provide all required fields to proceed.'))
        }

        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json(
                createError(errorCodes.badRequest, 'email', 'Please provide a valid email address.')
            );
        }

        // Validate password strength
        if (password.length < 6) {
            return res.status(400).json(
                createError(errorCodes.badRequest, 'password', 'Password must be at least 6 characters long.')
            );
        }

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            if (existingUser.isEmailVerified) {
                return res.status(409).json(
                    createError(errorCodes.conflict, 'email', 'An account with this email address already exists.')
                );
            } else {
                await User.deleteOne({ email });
            }
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 12);

        // Generate verification token
        const verificationToken = generateVerificationToken();

        // Prepare user data for Redis storage
        const userData = {
            username,
            email,
            password: hashedPassword,
            createdAt: new Date().toISOString()
        };

        // Store verification token and user data in Redis
        const storeResult = await storeVerificationToken(verificationToken, userData);
        if (!storeResult.success) {
            return res.status(500).json(
                createError(errorCodes.serverError, 'serverError', 'Failed to process registration. Please try again.')
            );
        }

        // Send verification email
        const emailResult = await sendVerificationEmail(email, username, verificationToken);
        if (!emailResult.success) {
            // Clean up Redis if email fails
            await redisClient.del(`email_verification:${verificationToken}`);
            return res.status(500).json(
                createError(errorCodes.serverError, 'email', 'Failed to send verification email. Please try again.')
            );
        }

        console.log(`Registration initiated for user: ${email}`);

        res.status(200).json({
            message: "Registration initiated successfully. Please check your email to verify your account.",
            email: email,
            expiresIn: "15 minutes"
        });

    } catch (error) {
        console.error("Error registering user:", error);
        if (error instanceof mongoose.Error.ValidationError) {
            res.status(400).json({ code: errorCodes.badRequest, errors: error.errors })
        }
        else {
            res.status(500).json(createError(errorCodes.serverError, 'serverError', 'An error occurred while registering user. Please try again later.'));
        }
    }
}

// Verify email endpoint
export const verifyEmail = async (req, res) => {
    try {
        const { token } = req.query;

        if (!token) {
            return res.status(400).json(
                createError(errorCodes.badRequest, 'token', 'Verification token is required.')
            );
        }

        // Get user data from Redis
        const key = `email_verification:${token}`;
        const userData = await redisClient.get(key);

        if (!userData) {
            return res.status(400).json(
                createError(errorCodes.badRequest, 'token', 'Invalid or expired verification token.')
            );
        }

        // Parse user data
        const parsedUserData = JSON.parse(userData);

        // Check if user already exists (race condition protection)
        const existingUser = await User.findOne({ email: parsedUserData.email });
        if (existingUser && existingUser.isEmailVerified) {
            // Clean up Redis
            await redisClient.del(key);
            return res.status(409).json(
                createError(errorCodes.conflict, 'email', 'Email address is already verified.')
            );
        }

        // Create new user with verified email
        const newUser = new User({
            username: parsedUserData.username,
            email: parsedUserData.email,
            password: parsedUserData.password,
            isEmailVerified: true,
            emailVerifiedAt: new Date()
        });

        await newUser.save();

        // Clean up Redis
        await redisClient.del(key);

        console.log('User email verified and account created successfully:', parsedUserData.email);

        res.status(201).json({
            message: "Email verified successfully! Your account has been created.",
            user: {
                id: newUser._id,
                username: newUser.username,
                email: newUser.email,
                isEmailVerified: newUser.isEmailVerified
            }
        });

    } catch (error) {
        console.error("Error verifying email:", error);

        if (error instanceof mongoose.Error.ValidationError) {
            return res.status(400).json({
                code: errorCodes.badRequest,
                errors: error.errors
            });
        }

        res.status(500).json(
            createError(errorCodes.serverError, 'serverError', 'An error occurred while verifying email. Please try again later.')
        );
    }
}

// Resend verification email
export const resendVerificationEmail = async (req, res) => {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json(
                createError(errorCodes.badRequest, 'email', 'Email address is required.')
            );
        }

        // Check if user exists and is already verified
        const existingUser = await User.findOne({ email });
        if (existingUser && existingUser.isEmailVerified) {
            return res.status(400).json(
                createError(errorCodes.badRequest, 'email', 'Email address is already verified.')
            );
        }

        // Check if there's a pending verification in Redis
        const pattern = `email_verification:*`;
        const keys = await redisClient.keys(pattern);

        let existingToken = null;
        for (const key of keys) {
            const userData = await redisClient.get(key);
            if (userData) {
                const parsedData = JSON.parse(userData);
                if (parsedData.email === email) {
                    existingToken = key.split(':')[1];
                    break;
                }
            }
        }

        if (!existingToken) {
            return res.status(404).json(
                createError(errorCodes.notFound, 'email', 'No pending verification found for this email address.')
            );
        }

        // Get user data and resend email
        const userData = JSON.parse(await redisClient.get(`email_verification:${existingToken}`));
        const emailResult = await sendVerificationEmail(email, userData.username, existingToken);

        if (!emailResult.success) {
            return res.status(500).json(
                createError(errorCodes.serverError, 'email', 'Failed to resend verification email. Please try again.')
            );
        }

        res.status(200).json({
            message: "Verification email resent successfully. Please check your email.",
            email: email,
            expiresIn: "15 minutes"
        });

    } catch (error) {
        console.error("Error resending verification email:", error);
        res.status(500).jsn(
            createError(errorCodes.serverError, 'serverError', 'An error occurred while resending verification email.')
        );
    }
};

const generateAccessAndRefreshTokens = async (id) => {
    try {
        const user = await User.findById(id);
        const accessToken = user.generateAccessToken();
        const refreshToken = user.generateRefreshToken();
        user.refreshToken = refreshToken;
        await user.save();
        return { accessToken, refreshToken };
    } catch (error) {
        console.log('Error in generateAccessAndRefreshTokens: ', error);
        throw error;
    }
}

export const loginUser = async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json(createError(errorCodes.badRequest, 'input', 'Both email and password is required.'));
        }

        const existingUser = await User.findOne({ email });
        if (!existingUser) {
            return res.status(401).json(createError(errorCodes.unauthorized, 'credentials', 'Invalid username or password.'));
        }

        const isValidPassword = await bcrypt.compare(password, existingUser.password);
        if (!isValidPassword) {
            return res.status(401).json(createError(errorCodes.unauthorized, 'credentials', 'Invalid username or password.'));
        }

        const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(existingUser._id);
        const { password: _, ...safeUser } = existingUser.toObject();

        res.status(200)
            .cookie('Auth_Access_Token', accessToken, { ...cookieOptions, maxAge: env.accessTokenMaxAge })
            .cookie('Auth_Refresh_Token', refreshToken, { ...cookieOptions, maxAge: env.refreshTokenMaxAge })
            .json({ user: safeUser, accessToken, refreshToken });

    } catch (error) {
        console.log('Error while authenticating user:', error);
        res.status(500).json(createError(errorCodes.serverError, 'serverError', 'An error occurred while authenticating user. Please try again later.'));
    }
}

const PASSWORD_RESET_EXPIRY = 30 * 60;

// Generate password reset token
const generatePasswordResetToken = () => {
    return crypto.randomBytes(32).toString('hex');
};

const sendPasswordResetEmail = async (email, username, resetToken) => {
    console.log({ reset_url: env.frontend_url })
    const reset_url = `${env.frontend_url}/reset-password?token=${resetToken}`;

    const emailData = {
        Messages: [{
            From: {
                Email: env.from_email,
                Name: env.from_name || 'Excel Analytics'
            },
            To: [{
                Email: email,
                Name: username
            }],
            Subject: 'Reset Your Password - Excel Analytics',
            "TemplateID": 7034865,
            "TemplateLanguage": true,
            "Subject": "Reset Your Password - Excel Analytics",
            "Variables": {
                reset_url,
                username
            }
        }]
    };

    try {
        const result = await mailjetClient.post('send', { version: 'v3.1' }).request(emailData);
        console.log('Password reset email sent successfully:', result.body);
        return { success: true };
    } catch (error) {
        console.error('Error sending password reset email:', error);
        return { success: false, error: error.message };
    }
};

// Store password reset token in Redis
const storePasswordResetToken = async (token, userData) => {
    try {
        const key = `password_reset:${token}`;
        await redisClient.setex(key, PASSWORD_RESET_EXPIRY, JSON.stringify(userData));
        return { success: true };
    } catch (error) {
        console.error('Error storing password reset token:', error);
        return { success: false, error: error.message };
    }
};

// Initiate password reset
export const forgotPassword = async (req, res) => {
    try {
        const { email } = req.body;

        // Validate email
        if (!email) {
            return res.status(400).json(
                createError(errorCodes.badRequest, 'email', 'Email address is required.')
            );
        }

        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json(
                createError(errorCodes.badRequest, 'email', 'Please provide a valid email address.')
            );
        }

        // Check if user exists and is verified
        const user = await User.findOne({ email, isEmailVerified: true });
        if (!user) {
            // For security, we don't reveal if email exists or not
            return res.status(200).json({
                message: "If an account with this email exists, a password reset link has been sent."
            });
        }

        // Check for existing password reset token (rate limiting)
        const existingTokenPattern = `password_reset:*`;
        const existingKeys = await redisClient.keys(existingTokenPattern);

        for (const key of existingKeys) {
            const tokenData = await redisClient.get(key);
            if (tokenData) {
                const parsedData = JSON.parse(tokenData);
                if (parsedData.email === email) {
                    const timeLeft = await redisClient.ttl(key);
                    if (timeLeft > 25 * 60) { // If less than 5 minutes have passed
                        return res.status(429).json(
                            createError(errorCodes.tooManyRequests, 'email', 'Password reset email already sent. Please wait before requesting another.')
                        );
                    }
                    // Remove old token
                    await redisClient.del(key);
                    break;
                }
            }
        }

        // Generate reset token
        const resetToken = generatePasswordResetToken();

        // Prepare reset data
        const resetData = {
            userId: user._id.toString(),
            email: user.email,
            username: user.username,
            requestedAt: new Date().toISOString()
        };

        // Store reset token in Redis
        const storeResult = await storePasswordResetToken(resetToken, resetData);
        if (!storeResult.success) {
            return res.status(500).json(
                createError(errorCodes.serverError, 'serverError', 'Failed to process password reset request. Please try again.')
            );
        }

        // Send reset email
        const emailResult = await sendPasswordResetEmail(user.email, user.username, resetToken);
        if (!emailResult.success) {
            // Clean up Redis if email fails
            await redisClient.del(`password_reset:${resetToken}`);
            return res.status(500).json(
                createError(errorCodes.serverError, 'email', 'Failed to send password reset email. Please try again.')
            );
        }

        console.log(`Password reset initiated for user: ${email}`);

        res.status(200).json({
            message: "If an account with this email exists, a password reset link has been sent.",
            expiresIn: "30 minutes"
        });

    } catch (error) {
        console.error("Error in forgot password:", error);
        res.status(500).json(
            createError(errorCodes.serverError, 'serverError', 'An error occurred while processing password reset request.')
        );
    }
};

// Reset password with token
export const resetPassword = async (req, res) => {
    try {
        const { token, newPassword } = req.body;

        // Validate inputs
        if (!token || !newPassword) {
            return res.status(400).json(
                createError(errorCodes.badRequest, 'input', 'All fields are required.')
            );
        }

        // Validate password strength
        if (newPassword.length < 6) {
            return res.status(400).json(
                createError(errorCodes.badRequest, 'password', 'Password must be at least 6 characters long.')
            );
        }

        // Get reset data from Redis
        const key = `password_reset:${token}`;
        const resetData = await redisClient.get(key);

        if (!resetData) {
            return res.status(400).json(
                createError(errorCodes.badRequest, 'token', 'Invalid or expired password reset token.')
            );
        }

        // Parse reset data
        const parsedResetData = JSON.parse(resetData);

        // Find user
        const user = await User.findById(parsedResetData.userId);
        if (!user || !user.isEmailVerified) {
            await redisClient.del(key);
            return res.status(404).json(
                createError(errorCodes.notFound, 'user', 'User not found or not verified.')
            );
        }

        // Hash new password
        const hashedPassword = await bcrypt.hash(newPassword, 12);

        // Update user password
        await User.findByIdAndUpdate(user._id, {
            password: hashedPassword,
            passwordChangedAt: new Date()
        });

        // Clean up Redis token
        await redisClient.del(key);

        // Invalidate any other password reset tokens for this user
        const allResetKeys = await redisClient.keys('password_reset:*');
        for (const resetKey of allResetKeys) {
            const data = await redisClient.get(resetKey);
            if (data) {
                const tokenData = JSON.parse(data);
                if (tokenData.userId === user._id.toString()) {
                    await redisClient.del(resetKey);
                }
            }
        }

        console.log('Password reset successful for user:', user.email);

        res.status(200).json({
            message: "Password reset successful! You can now sign in with your new password."
        });

    } catch (error) {
        console.error("Error resetting password:", error);
        res.status(500).json(
            createError(errorCodes.serverError, 'serverError', 'An error occurred while resetting password.')
        );
    }
};

// Verify reset token (optional - for frontend validation)
export const verifyResetToken = async (req, res) => {
    try {
        const { token } = req.query;

        if (!token) {
            return res.status(400).json(
                createError(errorCodes.badRequest, 'token', 'Reset token is required.')
            );
        }

        // Check if token exists in Redis
        const key = `password_reset:${token}`;
        const resetData = await redisClient.get(key);

        if (!resetData) {
            return res.status(400).json(
                createError(errorCodes.badRequest, 'token', 'Invalid or expired password reset token.')
            );
        }

        const parsedData = JSON.parse(resetData);
        const timeLeft = await redisClient.ttl(key);

        res.status(200).json({
            valid: true,
            email: parsedData.email,
            expiresIn: `${Math.floor(timeLeft / 60)} minutes`
        });

    } catch (error) {
        console.error("Error verifying reset token:", error);
        res.status(500).json(
            createError(errorCodes.serverError, 'serverError', 'An error occurred while verifying token.')
        );
    }
};

export const logoutUser = async (req, res) => {
    try {
        await User.findByIdAndUpdate(req.user._id, { refreshToken: null });
        return res
            .status(200)
            .clearCookie('Auth_Access_Token', cookieOptions)
            .clearCookie('Auth_Refresh_Token', cookieOptions)
            .json({ message: 'Logged out successfully' });
    } catch (error) {
        return res
            .status(500)
            .json(createError(errorCodes.serverError, 'serverError', 'An error occurred while logging out. Please try again later.'));
    }
};

export const handleTokenRefresh = async (req, res) => {
    try {
        const incomingRefreshToken = req.cookies.Auth_Refresh_Token || req.body?.refreshToken;
        console.log({ incomingRefreshToken });

        if (!incomingRefreshToken) {
            return res.status(401)
                .clearCookie('Auth_Refresh_Token', cookieOptions)
                .json(createError(
                    errorCodes.tokenMissing,
                    'refreshToken',
                    'Access denied, A valid token is required.'
                ));
        }

        const decodedRefreshToken = jwt.verify(incomingRefreshToken, env.refreshTokenSecret);
        const existingUser = await User.findById(decodedRefreshToken.id, { refreshToken: 1 });


        if (!existingUser || incomingRefreshToken !== existingUser.refreshToken) {
            return res.status(401)
                .clearCookie('Auth_Refresh_Token', cookieOptions)
                .json(createError(
                    errorCodes.tokenInvalid,
                    'refreshToken',
                    'Access denied, A valid token is required.'
                ));
        }

        const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(existingUser._id);
        res.status(200)
            .cookie('Auth_Access_Token', accessToken, { ...cookieOptions, maxAge: env.accessTokenMaxAge })
            .cookie('Auth_Refresh_Token', refreshToken, { ...cookieOptions, maxAge: env.refreshTokenMaxAge })
            .json({ accessToken, refreshToken });
    }
    catch (error) {
        console.log('Error in handleTokenRefresh:', error);
        if (error instanceof jwt.TokenExpiredError) {
            res.status(401)
                .clearCookie('Auth_Refresh_Token', cookieOptions)
                .json(createError(
                    errorCodes.tokenExpired,
                    'refreshToken',
                    'Your access has temporarily expired. Reauthenticate to get back in!'
                ));
        }
        else if (error instanceof jwt.JsonWebTokenError) {
            res.status(401)
                .clearCookie('Auth_Refresh_Token', cookieOptions)
                .json(createError(
                    errorCodes.tokenTampered,
                    'refreshToken',
                    'It seems the token is corrupted or invalid.'
                ));
        }
        else {
            res.status(500)
                .json(createError(
                    errorCodes.serverError,
                    'serverError',
                    'An error occurred while authenticating your access. Please try again later.'
                ));
        }
    }
}

export const getUserProfile = async (req, res) => {
    try {
        const user = await User.findById(req.user._id, 'email username roles').lean();
        if (!user) {
            return res.status(404).json(createError(errorCodes.notFound, 'user', 'User not found.'));
        }
        return res.status(200).json({ user });
    } catch (error) {
        console.log('Error in getUserProfile:', error);
        return res.status(500).json(createError(errorCodes.serverError, 'serverError', 'An error occurred while fetching user profile.'));
    }
};

export const updateUser = async (req, res) => {
    try {
        const updateData = req.body;

        const updatedUser = await User.findByIdAndUpdate(
            updateData.id,
            { $set: updateData },
            { new: true, runValidators: true }
        );

        if (!updatedUser) {
            return res.status(404).json(createError(errorCodes.notFound, 'user', 'User not found.'));
        }

        return res.status(200).json(updatedUser);
    } catch (error) {
        console.log('Error in updateUser:', error);
        return res.status(500).json(createError(errorCodes.serverError, 'serverError', 'An error occurred while updating user.'));
    }
}

export const getUserAccessStatus = async (req, res) => {
    try {
        const userId = req.user.id;
        const [user, currentAnalysisCount, currentUploadCount] = await Promise.all([
            User.findById(userId).select('analysisLimit uploadLimit permissions role'),
            Analysis.countDocuments({ userId }),
            FileUpload.countDocuments({ userId })
        ]);

        if (!user) {
            return res.status(404).json(createError(errorCodes.notFound, 'user', 'User not found.'));
        }

        // Check if user has read-only permissions
        const isReadOnly = user.permissions === 'Read Only';
        const hasFullAccess = user.permissions === 'Full Access';

        const response = {
            permissions: {
                level: user.permissions,
                readOnly: isReadOnly,
                fullAccess: hasFullAccess,
                canUpload: hasFullAccess,
                canAnalyze: hasFullAccess,
            },
            uploads: {
                current: currentUploadCount,
                limit: user.uploadLimit === -1 ? 'unrestricted' : user.uploadLimit,
                unlimited: user.uploadLimit === -1,
                allowed: hasFullAccess
            },
            analyses: {
                current: currentAnalysisCount,
                limit: user.analysisLimit === -1 ? 'unrestricted' : user.analysisLimit,
                unlimited: user.analysisLimit === -1,
                allowed: hasFullAccess
            }
        };

        if (hasFullAccess) {
            if (user.uploadLimit !== -1) {
                response.uploads.remaining = Math.max(0, user.uploadLimit - currentUploadCount);
                response.uploads.limitReached = currentUploadCount >= user.uploadLimit;
            }

            if (user.analysisLimit !== -1) {
                response.analyses.remaining = Math.max(0, user.analysisLimit - currentAnalysisCount);
                response.analyses.limitReached = currentAnalysisCount >= user.analysisLimit;
            }
        } else {
            // For read-only users, indicate that actions are not allowed
            response.uploads.limitReached = true;
            response.analyses.limitReached = true;
            response.uploads.remaining = 0;
            response.analyses.remaining = 0;
        }


        const message = isReadOnly
            ? "User limits status retrieved successfully. Note: Account has read-only access."
            : "User limits status retrieved successfully.";


        res.status(200).json({
            message,
            accessStatus: response
        });

    } catch (error) {
        console.log('get user access status error: ', error);
        res.status(500).json(createError(errorCodes.serverError, 'serverError', 'An error occurred while retrieving user access status.'));
    }
};

const cleanupPhysicalFiles = async (filePaths) => {
    const deletePromises = filePaths.map(async (filePath) => {
        try {
            await fs.access(filePath); // Check if file exists
            await fs.unlink(filePath); // Delete the file
            console.log(`Successfully deleted file: ${filePath}`);
        } catch (error) {
            if (error.code === 'ENOENT') {
                console.log(`File not found (already deleted?): ${filePath}`);
            } else {
                console.error(`Error deleting file ${filePath}:`, error);
            }
        }
    });

    await Promise.allSettled(deletePromises);
};

export const deleteMyAccount = async (req, res) => {
    const session = await mongoose.startSession();

    try {
        const userId = req.user._id;
        const password = req.headers['x-password-confirmation'];

        // Require password confirmation for self-deletion
        if (!password) {
            return res.status(400).json(
                createError(errorCodes.badRequest, 'password', 'Password confirmation is required to delete your account.')
            );
        }

        const user = await User.findById(userId);
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(401).json(
                createError(errorCodes.unauthorized, 'password', 'Incorrect password. Please try again.')
            );
        }

        // Use the same transaction logic as deleteUser
        await session.withTransaction(async () => {
            const fileUploads = await FileUpload.find({ userId }).session(session);

            await Analysis.deleteMany({ userId }).session(session);
            await DataSet.deleteMany({ userId }).session(session);
            await FileUpload.deleteMany({ userId }).session(session);
            await User.findByIdAndDelete(userId).session(session);

            session.filePathsToDelete = fileUploads.map(file => file.filePath);
        });

        // Cleanup physical files
        if (session.filePathsToDelete && session.filePathsToDelete.length > 0) {
            await cleanupPhysicalFiles(session.filePathsToDelete);
        }

        console.log(`User ${userId} successfully deleted their own account`);

        // Clear authentication cookies since account is deleted
        res.status(200)
            .clearCookie('Auth_Access_Token')
            .clearCookie('Auth_Refresh_Token')
            .json({
                message: 'Your account and all associated data have been permanently deleted.',
                deletedUserId: userId
            });

    } catch (error) {
        console.error('Error in account deleteMyAccount:', error);
        res.status(500).json(
            createError(
                errorCodes.serverError,
                'serverError',
                'An error occurred while deleting your account. Please try again later.'
            )
        );
    } finally {
        await session.endSession();
    }
};