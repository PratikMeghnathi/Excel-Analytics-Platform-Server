import { connectDB, env } from './config/index.js';
import http from 'http';
import app from "./app.js";

(async () => {
    try {
        await connectDB();
        const server = http.createServer(app);

        server.listen(env.port, () => {
            console.log(`Server started at ${env.backend_url}${env.node_env === 'production' ? '' : ':' + env.port}`);
        })
    } catch (error) {
        console.log('Error occured during initializing the server: ', error);
        process.exit(1);
    }
})();