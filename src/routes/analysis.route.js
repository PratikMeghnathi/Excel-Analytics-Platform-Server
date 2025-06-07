import express from "express";
import { validateUser } from "../middlewares/index.js";
import { deleteAnalysis, getAiInsightsOfSheetById, getAiPromptTypes, getAllAnalyses, getAnalysisById, saveAnalysis } from "../controllers/index.js";

const analysisRouter = express.Router();
analysisRouter.post('/save', validateUser, saveAnalysis);
analysisRouter.get('/history', validateUser, getAllAnalyses);
analysisRouter.get('/:analaysisId/:dataSetId/:sheetIndex', validateUser, getAnalysisById);
analysisRouter.delete('/delete/:analysisId', validateUser, deleteAnalysis);


analysisRouter.get('/ai-insights/:dataSetId/:sheetIndex', validateUser, getAiInsightsOfSheetById);
analysisRouter.get('/ai-prompt-types', validateUser, getAiPromptTypes);


export default analysisRouter;
