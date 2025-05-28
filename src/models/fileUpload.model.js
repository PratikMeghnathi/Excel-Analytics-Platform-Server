import mongoose from "mongoose";

const fileUploadSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
        validate: {
            validator: async function (value) {
                const isExist = await mongoose.model('User').findById(value);
                return !!isExist;
            },
            message: "User does not exist."
        }
    },
    filename: {
        type: String,
        required: true
    },
    originalName: {
        type: String,
        required: true
    },
    fileSize: {
        type: Number,
        required: true
    },
    filePath: {
        type: String,
        required: true
    },
}, { timestamps: true });

const FileUpload = mongoose.model('FileUpload', fileUploadSchema);
export default FileUpload;