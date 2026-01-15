import express from "express";
import cors from 'cors';
import cookieParser from 'cookie-parser';
import path from 'path';

import { adminRouter, analysisRouter, uploadRouter, userRouter } from "./routes/index.js";
import { __rootdir } from "./utils/index.js";
import { env } from "./config/index.js";

const app = express();

app.use((req, res, next) => {
    console.log('📨 Request from:', req.headers.origin);
    console.log('🔑 NODE_ENV:', env.node_env);
    console.log('🌐 Allowed origin:', env.frontend_url);
    next();
});

//cors middleware
app.use(cors({
    credentials: true,                              //allow credentials like cookies and all
    origin: [
        env.frontend_url
    ]
}));

//----parsers-----
app.use(cookieParser());                            //to parse cookies from the incoming request
app.use(express.json());                            //to parse incoming JSON requests (body parsing)
app.use(express.urlencoded({ extended: true }));    //to parse form data (URL-encoded), allowing nested data with extended: true

app.use(express.static(path.join(__rootdir, 'public')));  // for testing only (by hitting on localhost:8080/ you'll get .html)

//----routers-----
app.use('/api/user', userRouter);                   //user routes
app.use('/api/upload', uploadRouter);               //upload routes
app.use('/api/analysis', analysisRouter);           //analysis routes
app.use('/api/admin', adminRouter);                 //admin routes

// 404 fallback (for unmatched routes)
app.use((_, res) => {                               //if not routes match
    res.status(404).json({ code: 'error', message: 'Not Found' });
});

// Central error handler
app.use((err, _, res) => {
    console.error(err);
    res.status(500).json({ code: 'error', message: 'Internal server error' });
});

export default app;