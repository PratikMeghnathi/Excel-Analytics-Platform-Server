import express from "express";
import { registerUser, loginUser, handleTokenRefresh, logoutUser, getUserProfile, updateUser } from "../controllers/index.js";
import { validateUser } from "../middlewares/index.js";

const userRouter = express.Router();

userRouter.post('/auth/signup', registerUser);
userRouter.post('/auth/signin', loginUser);
userRouter.post('/auth/signout', validateUser, logoutUser);

userRouter.post('/auth/refresh', handleTokenRefresh);
userRouter.get('/profile', validateUser, getUserProfile);
userRouter.patch('/update-user', validateUser, updateUser);



// ------- test/development only routes ------------- //
userRouter.get('/validate', validateUser, (req, res) => {
    console.log(req.user);
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

export default userRouter;