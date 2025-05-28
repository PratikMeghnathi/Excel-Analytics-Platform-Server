import express from "express";
import { validateUser } from "../middlewares/index.js";
import { getDashboardAnalytics } from "../controllers/index.js";

const adminRouter = express.Router();
// adminRouter.get('/stats', adminDashboardStats);
adminRouter.get('/', getDashboardAnalytics);

export default adminRouter;