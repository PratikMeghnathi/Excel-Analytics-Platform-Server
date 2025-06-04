import express from "express";
import { registerUser, loginUser, handleTokenRefresh, logoutUser, getUserProfile, updateUser, getUserAccessStatus, deleteMyAccount, verifyEmail, resendVerificationEmail, verifyResetToken, resetPassword, forgotPassword } from "../controllers/index.js";
import { validateUser } from "../middlewares/index.js";
import User from "../models/user.model.js";

const userRouter = express.Router();

userRouter.post('/auth/signup', registerUser);
userRouter.get('/auth/verify-email', verifyEmail);
userRouter.post('/auth/resend-verification-email', resendVerificationEmail);

userRouter.post('/auth/signin', loginUser);
userRouter.post('/auth/signout', validateUser, logoutUser);
userRouter.post('/auth/refresh', handleTokenRefresh);

userRouter.post('/auth/forgot-password', forgotPassword);
userRouter.post('/auth/reset-password', resetPassword);
userRouter.get('/auth/verify-reset-token', verifyResetToken);

userRouter.get('/profile', validateUser, getUserProfile);
userRouter.patch('/update-user', validateUser, updateUser);
userRouter.get('/access-status', validateUser, getUserAccessStatus);

userRouter.delete('/delete-my-account', validateUser, deleteMyAccount);


// ------- test/development only routes ------------- //
userRouter.get('/validate', validateUser, (req, res) => {
    res.json(req.user);
})
//INSERT users
userRouter.post('/test-insert-user', async (req, res) => {
    try {
        const data = req.body;
        const isMultiple = Array.isArray(data);
        let result;
        if (isMultiple) {
            result = await User.insertMany(data);
        } else {
            const newUser = new User(data);
            result = await newUser.save();
        }
        res.json({ message: 'User added successfully: ', result });
    } catch (error) {
        console.log("Error in insert user: ", error);
        res.json({ message: 'Error adding user: ', error });
    }
});
//DELETE users
userRouter.delete('/test-delete-user', async (req, res) => {
    try {
        const { ids, all } = req.body;
        if (all) {
            const result = await User.deleteMany({});
            return res.status(200).json({ message: 'All users deleted', deletedCount: result.deletedCount });
        }
        if (!ids || !Array.isArray(ids) || ids.length === 0) {
            return res.status(400).json({ message: 'Provide array of user IDs or set all=true' });
        }
        const result = await User.deleteMany({ _id: { $in: ids } });
        res.status(200).json({ message: 'Selected users deleted', deletedCount: result.deletedCount });
    } catch (err) {
        console.error('Error deleting users:', err);
        res.status(500).json({ message: 'Internal server error' });
    }
});

userRouter.get('/migration', async (req, res) => {
    try {
        // Update uploadLimit: find documents where uploadLimit is a string (type 2)
        const uploadResult = await User.updateMany(
            { uploadLimit: { $type: "string" } }, // Find string values
            { $set: { uploadLimit: -1 } }
        );

        // Update analysisLimit: find documents where analysisLimit is a string (type 2)
        const analysisResult = await User.updateMany(
            { analysisLimit: { $type: "string" } }, // Find string values
            { $set: { analysisLimit: -1 } }
        );

        console.log(`Updated ${uploadResult.modifiedCount} users' uploadLimit`);
        console.log(`Updated ${analysisResult.modifiedCount} users' analysisLimit`);

        // Also handle null or undefined values
        const uploadNullResult = await User.updateMany(
            {
                $or: [
                    { uploadLimit: null },
                    { uploadLimit: { $exists: false } }
                ]
            },
            { $set: { uploadLimit: -1 } }
        );

        const analysisNullResult = await User.updateMany(
            {
                $or: [
                    { analysisLimit: null },
                    { analysisLimit: { $exists: false } }
                ]
            },
            { $set: { analysisLimit: -1 } }
        );
        console.log(`Updated ${uploadNullResult.modifiedCount} users' null uploadLimit`);
        console.log(`Updated ${analysisNullResult.modifiedCount} users' null analysisLimit`);

        res.json({ uploadNullResult, analysisNullResult })
    } catch (error) {
        res.json({ error })
        console.error('Migration error:', error);
    }
})

export default userRouter;