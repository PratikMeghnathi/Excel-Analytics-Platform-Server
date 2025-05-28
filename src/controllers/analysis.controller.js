import mongoose from "mongoose";
import { Analysis, DataSet } from "../models/index.js";
import { createError, errorCodes } from "../utils/index.js";

export const saveAnalysis = async (req, res) => {
    const { name, fileName, sheetName, sheetIndex, chartConfig, dataSample, dataSetId } = req.body;

    if (!name || !fileName || !sheetName || sheetIndex === undefined || !chartConfig || !dataSample || !dataSetId) {
        return res.status(400).json(createError(errorCodes.badRequest, 'input', 'Please complete all fields before saving your analysis.'));
    }

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
    try {
        const analysis = new Analysis({
            userId: req.user.id,
            name,
            filename: fileName,
            sheetName,
            chartConfig: config,
            dataSample,
            dataSetId,
            sheetIndex
        });

        await analysis.save();
        res.status(201).json({ message: 'Your analysis has been saved successfully.' });
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

        return res.status(200).json({
            success: true,
            message: "Your saved analyses have been retrieved successfully.",
            analyses,
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
        res.status(200).json({
            message: "The analysis data has been successfully retrieved.",
            rows: sheet.data,
        });
    }
    catch (error) {
        console.error('Error fetching analysis by id:', error);
        return res.status(500).json(createError(errorCodes.serverError, 'serverError', "An unexpected issue occurred while retrieving the analysis data. Please try again later."));
    }
}

export const deleteAnalysis = async (req, res) => {
    try {
        const { analysisId } = req.params;

        if (!mongoose.Types.ObjectId.isValid(analysisId)) {
            return res.status(400).json(createError(errorCodes.badRequest, 'deleteAnalysis', 'The analysis you’re trying to delete has an invalid ID. Please check and try again.'));
        }

        const deletedAnalysis = await Analysis.findByIdAndDelete(analysisId);
        if (!deletedAnalysis) {
            return res.status(404).json(createError(errorCodes.notFound, 'deleteAnalysis', 'We couldn’t find the analysis you’re trying to delete. It may have already been removed.'
            ));
        }

        res.status(200).json({ message: 'The analysis has been successfully deleted.' });
    } catch (error) {
        console.error('Error deleting analysis:', error);
        return res.status(500).json(createError(errorCodes.serverError, 'serverError', "An unexpected issue occurred while deleting the analysis. Please try again later."));
    }
};

