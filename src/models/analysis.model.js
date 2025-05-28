import mongoose from "mongoose";

const analysisSchema = new mongoose.Schema({
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
    dataSetId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'DataSet',
        required: true,
        validate: {
            validator: async function (value) {
                const isExist = await mongoose.model('DataSet').findById(value);
                return !!isExist;
            },
            message: "This dataset is not exists."
        }
    },
    name: {
        type: String,
        required: true
    },
    filename: {
        type: String,
        required: true
    },
    sheetName: {
        type: String
    },
    sheetIndex: {
        type: Number
    },
    chartConfig: {
        chartType: String,
        xAxis: String,
        yAxis: String,
        zAxis: String,
        title: String,
        additionalOptions: Object
    },
    dataSample: {
        headers: [String],
        rows: Array, // Just 5-10 rows for reference
        totalRows: Number
    },
}, { timestamps: true });



const Analysis = mongoose.model('Analysis', analysisSchema);
export default Analysis;