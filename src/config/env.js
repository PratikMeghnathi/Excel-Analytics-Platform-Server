import dotenv from 'dotenv';
dotenv.config();

const env = {
    port: process.env.PORT || 5000,
    node_env: process.env.NODE_ENV,

    mongodb_url: process.env.MONGODB_URI,
    frontend_url: process.env.NODE_ENV === 'production' ? process.env.FRONTEND_URL : process.env.FRONTEND_LOCAL_URL,
    backend_url: process.env.NODE_ENV === 'production' ? process.env.BACKEND_URL : process.env.BACKEND_LOCAL_URL,

    accessTokenSecret: process.env.ACCESS_TOKEN_SECRET || '',
    accessTokenValidity: process.env.ACCESS_TOKEN_VALIDITY || '1h',
    accessTokenMaxAge: process.env.ACCESS_TOKEN_MAX_AGE || 86400000,

    refreshTokenSecret: process.env.REFRESH_TOKEN_SECRET || '',
    refreshTokenValidity: process.env.REFRESH_TOKEN_VALIDITY || '1d',
    refreshTokenMaxAge: process.env.REFRESH_TOKEN_MAX_AGE || 604800000,

    redis_username: process.env.REDIS_USERNAME,
    redis_password: process.env.REDIS_PASSWORD,
    redis_host: process.env.REDIS_HOST,
    redis_port: process.env.REDIS_PORT,

    mailjet_api_key: process.env.MAILJET_API_KEY,
    mailjet_secret_key: process.env.MAILJET_SECRET_KEY,
    from_email: process.env.FROM_EMAIL,
    from_name: process.env.FROM_NAME,

    geminiApiKey: process.env.GEMINI_API_KEY || '',
};

export default env;