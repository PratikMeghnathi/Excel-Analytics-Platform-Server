import mongoose from "mongoose";
import jwt from "jsonwebtoken";

import { env } from "../config/index.js";

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: [true, "Username is required to personalize your account."]
    },
    email: {
        type: String,
        required: [true, "Please provide your email address."],
        unique: true,
        match: [/^[^\s@]+@[^\s@]+\.[^\s@]+$/, "Please enter a valid email address."]
    },
    isEmailVerified: {
        type: Boolean,
        default: false
    },
    emailVerifiedAt: {
        type: Date,
        default: null
    },
    password: {
        type: String,
        required: [true, "A password is required to create an account."],
        minlength: [6, "Password must be at least 6 characters long."]
    },
    passwordChangedAt: {
        type: Date,
        default: null
    },
    role: {
        type: String,
        enum: ['user', 'admin'],
        default: 'user'
    },
    permissions: {
        type: String,
        enum: ['Full Access', 'Read Only'],
        default: 'Full Access'
    },
    uploadLimit: {
        type: Number,
        default: -1,
        validate: {
            validator: (value) => Number.isInteger(value) && value >= -1,
            message: 'Upload limit must be -1 (unrestricted) or a positive integer.'
        }
    },
    analysisLimit: {
        type: Number,
        default: -1,
        validate: {
            validator: (value) => Number.isInteger(value) && value >= -1,
            message: 'Analysis limit must be -1 (unrestricted) or a positive integer.'
        }
    },
    refreshToken: {
        type: String,
    }
}, { timestamps: true });

userSchema.methods.generateAccessToken = function () {
    return jwt.sign({ id: this._id }, env.accessTokenSecret, { expiresIn: env.accessTokenValidity });
}
userSchema.methods.generateRefreshToken = function () {
    return jwt.sign({ id: this._id }, env.refreshTokenSecret, { expiresIn: env.refreshTokenValidity });
}

const User = mongoose.model('User', userSchema);
export default User;