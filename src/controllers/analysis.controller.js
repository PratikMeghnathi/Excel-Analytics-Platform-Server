import mongoose from "mongoose";
import { Analysis, DataSet, User } from "../models/index.js";
import { createError, errorCodes } from "../utils/index.js";
import { GoogleGenAI } from "@google/genai";
import { env } from "../config/index.js";

const checkAnalysisLimit = async (userId) => {
    try {
        const user = await User.findById(userId).select('analysisLimit');

        if (!user) {
            return {
                allowed: false,
                message: 'User not found.'
            };
        }

        // If analysis limit is -1 (unrestricted), allow save
        if (user.analysisLimit === -1) {
            return {
                allowed: true,
                message: 'Analysis save allowed - no limit set.'
            };
        }

        // Count current analyses for the user
        const currentAnalysisCount = await Analysis.countDocuments({ userId });

        // Check if user has reached their limit
        if (currentAnalysisCount >= user.analysisLimit) {
            return {
                allowed: false,
                message: `Analysis limit reached. You have saved ${currentAnalysisCount} analyses out of your ${user.analysisLimit} analysis limit.`
            };
        }

        return {
            allowed: true,
            message: `Analysis save allowed. You have ${user.analysisLimit - currentAnalysisCount} analyses remaining.`
        };

    } catch (error) {
        console.error('Error checking analysis limit:', error);
        return {
            allowed: false,
            message: 'Error checking analysis permissions.'
        };
    }
};

export const saveAnalysis = async (req, res) => {
    if (req.user.role !== 'admin' && req.user.permissions === 'Read Only') {
        return res.status(403).json(createError(errorCodes.forbidden, 'permission', 'You do not have permission to save analyses.'));
    }

    // Check analysis limit before processing
    const analysisLimitCheck = await checkAnalysisLimit(req.user.id);
    if (!analysisLimitCheck.allowed) {
        return res.status(429).json(createError(errorCodes.tooManyRequests, 'analysisLimit', analysisLimitCheck.message));
    }

    // Required fields validation
    const { name, fileName, sheetName, sheetIndex, chartConfig, dataSample, dataSetId, aiInsights } = req.body;

    if (!name || !fileName || !sheetName || sheetIndex === undefined || !chartConfig || !dataSample || !dataSetId) {
        return res.status(400).json(createError(errorCodes.badRequest, 'input', 'Please complete all fields before saving your analysis.'));
    }

    // Chart config validation
    let config;
    try {
        config = typeof chartConfig === "string"
            ? JSON.parse(chartConfig)
            : chartConfig;

        if (!config || typeof config !== 'object') {
            return res.status(400).json(createError(errorCodes.badRequest, 'chartConfig', 'There was a problem with your chart settings. Please adjust and try again.'));
        }
    } catch (err) {
        return res.status(400).json(createError(errorCodes.badRequest, 'chartConfig', 'Your chart settings are invalid. Please try setting them up again.'));
    }

    // Data sample validation
    const isValidDataSample = (
        dataSample &&
        typeof dataSample === 'object' &&
        Array.isArray(dataSample.headers) &&
        dataSample.headers.length > 0 &&
        Array.isArray(dataSample.rows) &&
        dataSample.rows.length > 0 &&
        typeof dataSample.totalRows === 'number'
    );

    if (!isValidDataSample) {
        return res.status(400).json(
            createError(errorCodes.badRequest, 'dataSample', 'We couldn’t process a preview of your chart data. Please try again.')
        );
    }

    // AI Insights validation
    let validatedAiInsights = null;
    if (aiInsights) {
        const isValidAiInsights = (
            aiInsights &&
            typeof aiInsights === 'object' &&
            aiInsights.promptType &&
            aiInsights.insights &&
            typeof aiInsights.insights === 'string' &&
            aiInsights.insights.trim().length > 0
        );

        if (!isValidAiInsights) {
            return res.status(400).json(
                createError(errorCodes.badRequest, 'aiInsights', 'AI insights data is invalid. Please regenerate insights and try again.')
            );
        }
        validatedAiInsights = {
            promptType: aiInsights.promptType,
            insights: aiInsights.insights.trim(),
            generatedAt: aiInsights.generatedAt ? new Date(aiInsights.generatedAt) : new Date(),
            metadata: aiInsights.metadata || {}
        };
    }

    try {
        const analysisData = {
            userId: req.user.id,
            name,
            filename: fileName,
            sheetName,
            chartConfig: config,
            dataSample,
            dataSetId,
            sheetIndex
        };


        // Only if aiInsights 
        if (validatedAiInsights) {
            analysisData.aiInsights = validatedAiInsights;
        }

        const analysis = new Analysis(analysisData);
        await analysis.save();

        const responseMessage = validatedAiInsights
            ? 'Your analysis with AI insights has been saved successfully.'
            : 'Your analysis has been saved successfully.';

        res.status(201).json({
            message: responseMessage,
            analysisId: analysis._id,
            hasAiInsights: !!validatedAiInsights
        });
    } catch (err) {
        console.error('Error saving analysis:', err);
        return res.status(500).json(createError(errorCodes.serverError, 'serverError', 'Something went wrong while saving your analysis. Please try again.'));
    }
}


export const getAllAnalyses = async (req, res) => {
    try {
        const userId = req.user.id;
        let limit = req.query.limit;
        const query = Analysis.find({ userId }).sort({ createdAt: -1 });

        if (limit) {
            const parsedLimit = parseInt(limit, 10);
            if (!isNaN(parsedLimit) && parsedLimit > 0) {
                query.limit(parsedLimit);
            }
        }
        const [analyses, totalCount] = await Promise.all([
            query.exec(),
            Analysis.countDocuments({ userId })
        ]);

        const analysesWithFlags = analyses.map(analysis => {
            const { aiInsights, ...analysisWithoutInsights } = analysis.toObject();
            return {
                ...analysisWithoutInsights,
                hasAiInsights: !!(analysis.aiInsights && analysis.aiInsights.insights)
            }
        });


        return res.status(200).json({
            success: true,
            message: "Your saved analyses have been retrieved successfully.",
            analyses: analysesWithFlags,
            totalCount
        });
    } catch (err) {
        console.error('Error fetching analyses:', err);
        return res.status(500).json(createError(errorCodes.serverError, 'serverError', 'We couldn’t load your saved analyses. Please try again later.'));
    }
};

export const getAnalysisById = async (req, res) => {
    try {
        const { dataSetId, sheetIndex } = req.params;
        const parsedIndex = parseInt(sheetIndex, 10);
        if (isNaN(parsedIndex) || parsedIndex < 0) {
            return res.status(400).json(createError(
                errorCodes.badRequest,
                'analysis',
                "We encountered an issue processing your request. Please verify the selected analysis and try again."
            ));
        }

        const dataSet = await DataSet.findById(dataSetId);
        if (!dataSet) {
            return res.status(404).json(createError(errorCodes.notFound, 'analysis', "The requested dataset is currently unavailable. It may have been removed or does not exist."));
        }

        if (parsedIndex >= dataSet.sheets.length) {
            return res.status(404).json(createError(
                errorCodes.notFound,
                'analysis',
                "The selected sheet data could not be located. Please review your selection and try again."
            ));
        }

        const sheet = dataSet.sheets[parsedIndex];

        // Check if there are any saved analyses for this dataSet and sheetIndex that might have AI insights
        const savedAnalysis = await Analysis.findOne({
            dataSetId: dataSetId,
        }).sort({ createdAt: -1 });

        const response = {
            message: "The analysis data has been successfully retrieved.",
            rows: sheet.data,
        };

        // Include AI insights if available in saved analysis
        if (savedAnalysis && savedAnalysis.aiInsights && savedAnalysis.aiInsights.insights) {
            response.aiInsights = {
                promptType: savedAnalysis.aiInsights.promptType,
                insights: savedAnalysis.aiInsights.insights,
                generatedAt: savedAnalysis.aiInsights.generatedAt,
                metadata: savedAnalysis.aiInsights.metadata
            };
            response.hasAiInsights = true;
        } else {
            response.hasAiInsights = false;
        }

        res.status(200).json(response);
    }
    catch (error) {
        console.error('Error fetching analysis by id:', error);
        return res.status(500).json(createError(errorCodes.serverError, 'serverError', "An unexpected issue occurred while retrieving the analysis data. Please try again later."));
    }
}

export const deleteAnalysis = async (req, res) => {
    try {
        if (req.user.role !== 'admin' && req.user.permissions === 'Read Only') {
            return res.status(403).json(createError(errorCodes.forbidden, 'permission', 'You do not have permission to delete analyses.'));
        }

        const { analysisId } = req.params;

        if (!mongoose.Types.ObjectId.isValid(analysisId)) {
            return res.status(400).json(createError(errorCodes.badRequest, 'deleteAnalysis', 'The analysis you’re trying to delete has an invalid ID. Please check and try again.'));
        }

        const deletedAnalysis = await Analysis.findByIdAndDelete(analysisId);
        if (!deletedAnalysis) {
            return res.status(404).json(createError(errorCodes.notFound, 'deleteAnalysis', 'We couldn’t find the analysis you’re trying to delete. It may have already been removed.'
            ));
        }

        // Check if the deleted analysis had AI insights
        const hasAiInsights = !!(deletedAnalysis.aiInsights && deletedAnalysis.aiInsights.insights);
        const message = hasAiInsights
            ? 'The analysis and its AI insights have been successfully deleted.'
            : 'The analysis has been successfully deleted.';

        res.status(200).json({ message });
    } catch (error) {
        console.error('Error deleting analysis:', error);
        return res.status(500).json(createError(errorCodes.serverError, 'serverError', "An unexpected issue occurred while deleting the analysis. Please try again later."));
    }
};

// AI Insights
const ai = new GoogleGenAI({ apiKey: env.geminiApiKey });

// AI Insight prompts for variety
const AI_PROMPTS = [{
    type: 'summary',
    prompt: (sheetName, headers, sampleData) => `
    Analyze this Excel sheet data and provide a concise business summary:

    Sheet Name: ${sheetName}
    Columns: ${headers.join(', ')}
    Sample Data (first 5 rows):
    ${sampleData.map(row => headers.map((header, i) => `${header}: ${row[i] || 'N/A'}`).join(', ')).join('\n')}

    Please provide:
    1. Key observations about the data
    2. Notable patterns or trends
    3. Data quality insights
    4. Business recommendations

    Keep the response professional and under 300 words.`
}, {
    type: 'trends',
    prompt: (sheetName, headers, sampleData) => `
    Focus on identifying trends and patterns in this Excel data:

    Sheet Name: ${sheetName}
    Columns: ${headers.join(', ')}
    Sample Data:
    ${sampleData.map(row => headers.map((header, i) => `${header}: ${row[i] || 'N/A'}`).join(', ')).join('\n')}
    
    Analyze and highlight:
    1. Statistical trends in numerical data
    2. Seasonal or time-based patterns (if applicable)
    3. Correlations between different columns
    4. Outliers or anomalies
    
    Provide actionable insights in a clear, structured format.`
}, {
    type: 'performance',
    prompt: (sheetName, headers, sampleData) => `
    Provide a performance-focused analysis of this Excel data:

    Sheet Name: ${sheetName}
    Data Structure: ${headers.join(', ')}
    Sample Records:
    ${sampleData.map(row => headers.map((header, i) => `${header}: ${row[i] || 'N/A'}`).join(', ')).join('\n')}

    Focus on:
    1. Performance metrics and KPIs
    2. Areas of strength and improvement
    3. Comparative analysis (if applicable)
    4. Strategic recommendations

    Present findings in a business-oriented manner with clear next steps.`
}, {
    type: 'overview',
    prompt: (sheetName, headers, sampleData) => `
    Generate a comprehensive overview of this Excel sheet:

    Sheet: ${sheetName}
    Structure: ${headers.join(', ')} 
    Data Preview:
    ${sampleData.map(row => headers.map((header, i) => `${header}: ${row[i] || 'N/A'}`).join(', ')).join('\n')}

    Provide:
    1. Dataset characteristics and structure
    2. Data completeness and quality assessment
    3. Key insights and interesting findings
    4. Potential use cases for this data

    Format as a professional data analysis report summary.`
}];

const prepareDataForAnalysis = (sheet) => {
    const headers = sheet.data[0] || [];
    const sampleData = sheet.data.slice(1, 6); // First 5 data rows

    return {
        headers,
        sampleData,
        totalRows: sheet.data.length - 1, // Excluding header
        dataQuality: {
            hasHeaders: headers.length > 0,
            hasData: sampleData.length > 0,
            columnCount: headers.length
        }
    };
};


export const getAiInsightsOfSheetById = async (req, res) => {
    try {
        if (req.user.role !== 'admin' && req.user.permissions === 'Read Only') {
            return res.status(403).json(createError(errorCodes.forbidden, 'permission', 'You do not have permission to generate AI-INSIGHTS.'));
        }

        const { dataSetId, sheetIndex } = req.params;
        const { promptType = 'summary' } = req.query;

        const parsedIndex = parseInt(sheetIndex, 10);
        if (isNaN(parsedIndex) || parsedIndex < 0) {
            return res.status(400).json(createError(
                errorCodes.badRequest,
                'analysis',
                "We encountered an issue processing your request. Please verify the selected analysis and try again."
            ));
        }

        const dataSet = await DataSet.findById(dataSetId);
        if (!dataSet) {
            return res.status(404).json(createError(errorCodes.notFound, 'analysis', "The requested dataset is currently unavailable. It may have been removed or does not exist."));
        }

        if (parsedIndex >= dataSet.sheets.length) {
            return res.status(404).json(createError(
                errorCodes.notFound,
                'analysis',
                "The selected sheet data could not be located. Please review your selection and try again."
            ));
        }

        const sheet = dataSet.sheets[parsedIndex];
        const sheetName = sheet.sheetName || `Sheet ${parsedIndex + 1}`;

        const analysisData = prepareDataForAnalysis(sheet);
        if (!analysisData.dataQuality.hasHeaders || !analysisData.dataQuality.hasData) {
            return res.status(400).json(createError(
                errorCodes.badRequest,
                'dataQuality',
                "Insufficient data in the sheet for AI analysis."
            ));
        }

        const selectedPrompt = AI_PROMPTS.find(p => p.type === promptType) || AI_PROMPTS[0];
        const prompt = selectedPrompt.prompt(sheetName, analysisData.headers, analysisData.sampleData);

        const result = await ai.models.generateContent({
            model: 'gemini-2.0-flash-001',
            contents: prompt,
        });
        const rawInsights = result.text;

        // Clean up formatting
        const insights = rawInsights
            .replace(/\*\*/g, '')
            .replace(/\#\#/g, '')
            .replace(/\*/g, '•')
            .trim();

        // Prepare response
        const response = {
            success: true,
            message: "AI insights generated successfully.",
            data: {
                sheetName,
                promptType: selectedPrompt.type,
                insights: insights,
                metadata: {
                    totalRows: analysisData.totalRows,
                    columnCount: analysisData.dataQuality.columnCount,
                    headers: analysisData.headers,
                    analysisDate: new Date().toISOString()
                }
            }
        };

        res.status(200).json(response);
    }
    catch (error) {
        console.error('Error generating ai insights:', error);

        // Handle specific AI API errors
        if (error.message?.includes('API_KEY')) {
            return res.status(500).json(createError(
                errorCodes.serverError,
                'aiService',
                "AI service configuration error. Please contact support."
            ));
        }

        if (error.message?.includes('QUOTA_EXCEEDED')) {
            return res.status(429).json(createError(
                errorCodes.tooManyRequests,
                'aiQuota',
                "AI service quota exceeded. Please try again later."
            ));
        }

        if (error.message?.includes('503') || error.message?.includes('overloaded')) {
            return res.status(503).json(createError(
                errorCodes.serviceUnavailable,
                'aiService',
                "AI service is temporarily overloaded. Please try again in a few minutes."
            ));
        }

        return res.status(500).json(createError(
            errorCodes.serverError,
            'serverError',
            "Unable to generate AI insights at this time. Please try again later."
        ));
    }
}

const getPromptDescription = (type) => {
    const descriptions = {
        summary: "General business summary and key observations",
        trends: "Focus on patterns, trends, and statistical insights",
        performance: "Performance metrics and strategic recommendations",
        overview: "Comprehensive data structure and quality analysis"
    };
    return descriptions[type] || "Standard analysis";
};

export const getAiPromptTypes = async (req, res) => {
    try {
        const promptTypes = AI_PROMPTS.map(prompt => ({
            type: prompt.type,
            label: prompt.type.charAt(0).toUpperCase() + prompt.type.slice(1),
            description: getPromptDescription(prompt.type)
        }));

        res.status(200).json({
            message: "Available AI prompt types retrieved successfully.",
            promptTypes
        });
    } catch (error) {
        console.error('Error fetching prompt types:', error);
        return res.status(500).json(createError(
            errorCodes.serverError,
            'serverError',
            "Unable to fetch prompt types."
        ));
    }
};

