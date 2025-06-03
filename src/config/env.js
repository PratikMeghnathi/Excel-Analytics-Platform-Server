import dotenv from 'dotenv';
dotenv.config();

const env = {
    port: process.env.PORT || 5000,

    mongodbLocalURI: process.env.MONGODB_LOCAL_URI || '',
    mongodbCloudURI: process.env.MONGODB_CLOUD_URI || '',

    accessTokenSecret: process.env.ACCESS_TOKEN_SECRET || '',
    accessTokenValidity: process.env.ACCESS_TOKEN_VALIDITY || '1h',
    accessTokenMaxAge: process.env.ACCESS_TOKEN_MAX_AGE || 86400000,

    refreshTokenSecret: process.env.REFRESH_TOKEN_SECRET || '',
    refreshTokenValidity: process.env.REFRESH_TOKEN_VALIDITY || '1d',
    refreshTokenMaxAge: process.env.REFRESH_TOKEN_MAX_AGE || 604800000,

    geminiApiKey: process.env.GEMINI_API_KEY || '',
    frontend_url: process.env.NODE_ENV === 'production' ? process.env.FRONTEND_URL : process.env.FRONTEND_LOCAL_URL,
    backend_url: process.env.NODE_ENV === 'production' ? process.env.BACKEND_URL : process.env.BACKEND_LOCAL_URL
};

export default env;