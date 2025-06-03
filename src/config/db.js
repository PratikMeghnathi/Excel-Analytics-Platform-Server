import { connect } from 'mongoose';
import env from './env.js';

const connectDB = async () => {
    try {
        await connect(env.mongodb_url);
        console.log(`Successfully connected with database.`);
    } catch (error) {
        console.log(`Failed to connect with database. Error: ${error}`);
        process.exit(1);
    }
};

export default connectDB;