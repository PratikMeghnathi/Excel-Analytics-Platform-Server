import mongoose from "mongoose";
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken'

import { User } from "../models/index.js";
import { cookieOptions, createError, errorCodes } from "../utils/index.js";
import { env } from "../config/index.js";

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

export const registerUser = async (req, res) => {
    try {
        const { username, email, password } = req.body;
        if (!username || !email || !password) {
            return res.status(400).json(createError(errorCodes.badRequest, 'input', 'Please provide all required fields to proceed.'))
        }
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(409).json(createError(errorCodes.conflict, 'email', 'An account with this email address already exists.'))
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({
            username, email,
            password: hashedPassword
        });
        await newUser.save();

        console.log('User created successfully.')
        res.status(201).json({ message: "User created successfully." })
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
export const logoutUser = async (req, res) => {
    try {
        await User.findByIdAndUpdate(req.user._id, { refreshToken: null });
        return res
            .status(200)
            .clearCookie('Auth_Access_Token', cookieOptions)
            .clearCookie('Auth_Refresh_Token', cookieOptions)
            .json({ message: 'Logged out successfully' });
    } catch (error) {
        console.log('Error in logoutUser:', error);
        return res
            .status(500)
            .json(createError(errorCodes.serverError, 'serverError', 'An error occurred while logging out. Please try again later.'));
    }
};
export const handleTokenRefresh = async (req, res) => {
    try {
        const incomingRefreshToken = req.cookies.Auth_Refresh_Token || req.body?.refreshToken;
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