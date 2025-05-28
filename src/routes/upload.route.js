import express from "express";
import { validateUser } from "../middlewares/index.js";
import { getAllUploads, uploadExcelFile } from "../controllers/index.js";
import { DataSet, FileUpload } from "../models/index.js";

const uploadRouter = express.Router();
uploadRouter.post('/excel', validateUser, uploadExcelFile);
uploadRouter.get('/', validateUser, getAllUploads);


// ------- test/development only routes ------------- //
// DELETE fileupload/dataset
uploadRouter.delete('/test-delete-fileuploads-datasets', async (req, res) => {
    try {
        const { ids, all, collection } = req.body;

        let Model;
        if (collection === 'fileuploads') {
            Model = FileUpload;
        } else if (collection === 'datasets') {
            Model = DataSet;
        } else {
            return res.status(400).json({ message: `Invalid collection. Use "fileuploads" or "datasets".` });
        }

        if (all) {
            const result = await Model.deleteMany({});
            return res.status(200).json({ message: `All documents deleted from ${collection}`, deletedCount: result.deletedCount });
        }

        if (!Array.isArray(ids) || ids.length === 0) {
            return res.status(400).json({ message: 'Provide an array of IDs or set all=true' });
        }

        const result = await Model.deleteMany({ _id: { $in: ids } });
        return res.status(200).json({ message: `Selected documents deleted from ${collection}`, deletedCount: result.deletedCount });

    } catch (err) {
        console.error(`Error deleting from ${req.body.collection}:`, err);
        return res.status(500).json({ message: 'Internal server error' });
    }
});



export default uploadRouter;