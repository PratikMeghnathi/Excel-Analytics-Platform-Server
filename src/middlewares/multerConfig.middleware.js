import multer from "multer";
import path from "path";
import { __uploadsDir, createError, errorCodes } from "../utils/index.js";

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, __uploadsDir);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        const extension = path.extname(file.originalname);
        cb(null, file.fieldname + '-' + uniqueSuffix + extension);
    }
})

const fileFilter = (req, file, cb) => {
    const allowedTypes = [
        'application/vnd.ms-excel',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    ];

    if (!allowedTypes.includes(file.mimetype)) {
        const error = new Error('Uploaded file must be an Excel spreadsheet (.xls or .xlsx).');
        error.code = errorCodes.wrongType;
        return cb(error, false);
    }
    cb(null, true);
}

const upload = multer({
    storage, fileFilter,
    limits: {
        // fileSize: 500 * 1024, // 500KB file size limit
        fileSize: 10 * 1024 * 1024, // 10MB file size limit
    }
})

export default upload;