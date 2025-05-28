import jwt from 'jsonwebtoken';
import { cookieOptions, createError, errorCodes } from '../utils/index.js';
import { env } from '../config/index.js';
import { User } from '../models/index.js';


const validateUser = async (req, res, next) => {
    try {
        const incomingAccessToken = req.cookies?.Auth_Access_Token || req.headers?.authorization?.split(' ')[1];
        if (!incomingAccessToken) {
            return res.status(401)
                .clearCookie('Auth_Access_Token', cookieOptions)
                .clearCookie('Auth_Refresh_Token', cookieOptions)
                .json(createError(
                    errorCodes.tokenMissing,
                    'accessToken',
                    'Access denied, A valid token is required.'
                ));
        }

        const decodedAccessToken = jwt.verify(incomingAccessToken, env.accessTokenSecret);
        const existingUser = await User.findById(decodedAccessToken.id);
        if (!existingUser) {
            return res.status(401)
                .clearCookie('Auth_Access_Token', cookieOptions)
                .clearCookie('Auth_Refresh_Token', cookieOptions)
                .json(createError(
                    errorCodes.tokenInvalid,
                    'accessToken',
                    'Access denied, A valid token is required.'
                ));
        }
        req.user = existingUser;
        next();
    } catch (error) {
        console.log('Error in validateUser: ', error);
        if (error?.name == 'TokenExpiredError') {
            res.status(401)
                .clearCookie('Auth_Access_Token', cookieOptions)
                .json(createError(
                    errorCodes.tokenExpired,
                    'accessToken',
                    'Your access has temporarily expired. Reauthenticate to get back in!'
                ));
        }
        else if (error?.name == 'JsonWebTokenError') {
            res.status(401)
                .clearCookie('Auth_Access_Token', cookieOptions)
                .clearCookie('Auth_Refresh_Token', cookieOptions)
                .json(createError(
                    errorCodes.tokenTampered,
                    'accessToken',
                    'It seems the token is corrupted or invalid.'
                ));
        }
        else {
            res.status(500).json(createError(errorCodes.serverError, 'serverError', 'An error occurred while validating user, Please try again later.'));
        }
    }
}

export default validateUser;