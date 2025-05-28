import express from "express";
import { validateUser } from "../middlewares/index.js";
import { deleteAnalysis, getAllAnalyses, getAnalysisById, saveAnalysis } from "../controllers/index.js";

const analysisRouter = express.Router();
analysisRouter.post('/save', validateUser, saveAnalysis);
analysisRouter.get('/history', validateUser, getAllAnalyses);
analysisRouter.get('/:dataSetId/:sheetIndex', validateUser, getAnalysisById);
analysisRouter.delete('/delete/:analysisId', validateUser, deleteAnalysis);

export default analysisRouter;
