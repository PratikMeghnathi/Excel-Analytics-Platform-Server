import express from "express";
import { validateUser } from "../middlewares/index.js";
import { getAdminDashboardAnalytics } from "../controllers/index.js";

const adminRouter = express.Router();
adminRouter.get('/', validateUser, getAdminDashboardAnalytics);

export default adminRouter;