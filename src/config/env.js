import dotenv from 'dotenv';
dotenv.config();

const env = {
    port: process.env.PORT || 5000,

    mongodbLocalURI: process.env.MONGODB_LOCAL_URI || '',
    mongodbCloudURI: process.env.MONGODB_CLOUD_URI || '',

    accessTokenSecret: process.env.ACCESS_TOKEN_SECRET || '0a94c0ee9f9f4b179cb3c88e5e3b76021348d3abbe572079f3d3698c33a7a76f',
    accessTokenValidity: process.env.ACCESS_TOKEN_VALIDITY || '1h',
    accessTokenMaxAge: process.env.ACCESS_TOKEN_MAX_AGE || 86400000,

    refreshTokenSecret: process.env.REFRESH_TOKEN_SECRET || 'efcfb1c34ac2c59c6d814e72e946f4e9c9345b01f4cf1f5c8ff1523b39b1cf01',
    refreshTokenValidity: process.env.REFRESH_TOKEN_VALIDITY || '1d',
    refreshTokenMaxAge: process.env.REFRESH_TOKEN_MAX_AGE || 604800000,

};

export default env;