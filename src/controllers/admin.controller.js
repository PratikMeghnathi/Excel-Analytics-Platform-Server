import { Analysis, FileUpload, User } from "../models/index.js";

export const getDashboardAnalytics = async (req, res) => {
    try {
        const now = new Date();
        const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);

        // Parallel execution for optimal performance
        const [
            basicStats,
            userStats,
            analyticsStats
        ] = await Promise.all([
            // Basic Stats
            getBasicStats(),

            // User Stats
            getUserStats(),

            // Analytics & Reporting Stats
            getAnalyticsReportingStats(thirtyDaysAgo)
        ]);


        const response = {
            basicStats,
            userStats,
            analyticsStats,
            timestamp: now.toISOString()
        };

        res.status(200).json(response);

    } catch (error) {
        console.error('Dashboard analytics error:', error);
        res.status(500).json({
            error: 'Failed to fetch dashboard analytics',
            message: error.message
        });
    }
};

// Basic Stats: Total Users, Active Users, Total Uploads, Saved Analyses
const getBasicStats = async () => {
    const users = await User.find({ role: 'user' }, '_id');
    const userIds = users.map(user => user._id);

    const [totalUploads, savedAnalyses] = await Promise.all([
        FileUpload.countDocuments({ userId: { $in: userIds } }),
        Analysis.countDocuments({ userId: { $in: userIds } }),
    ]);

    return {
        totalUsers: userIds.length,
        totalUploads,
        savedAnalyses
    };
};


// User Stats: ID, Name, Permissions, Activity, Status
const getUserStats = async () => {
    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);

    const users = await User.aggregate([
        { $match: { role: 'user' } },
        {
            $lookup: {
                from: 'fileuploads',
                localField: '_id',
                foreignField: 'userId',
                as: 'uploads'
            }
        },
        {
            $lookup: {
                from: 'analyses',
                localField: '_id',
                foreignField: 'userId',
                as: 'analyses'
            }
        },
        {
            $addFields: {
                recentUploads: {
                    $filter: {
                        input: '$uploads',
                        as: 'upload',
                        cond: { $gte: ['$upload.createdAt', thirtyDaysAgo] }
                    }
                },
                recentAnalyses: {
                    $filter: {
                        input: '$analyses',
                        as: 'analysis',
                        cond: { $gte: ['$analysis.createdAt', thirtyDaysAgo] }
                    }
                }
            }
        },
        {
            $project: {
                _id: 1,
                name: '$username',
                email: '$email',
                permissions: 1,
                activity: {
                    uploads: { $size: '$uploads' },
                    savedAnalyses: { $size: '$analyses' },
                    recentActivity: {
                        uploads: { $size: '$recentUploads' },
                        analyses: { $size: '$recentAnalyses' }
                    }
                },
                lastActivity: {
                    $max: [
                        { $max: '$uploads.createdAt' },
                        { $max: '$analyses.createdAt' }
                    ]
                },
                uploadLimit: '$uploadLimit',
                analysisLimit: '$analysisLimit'
            }
        },
        { $sort: { 'activity.total': -1 } }
    ]);

    return users;
};

// Analytics & Reporting Stats: Upload Frequency, Peak Upload Time, Usage Rate
const getAnalyticsReportingStats = async (thirtyDaysAgo) => {
    const [
        totalUsers,
        totalUploads,
        activeUsers,
        peakUploadTime
    ] = await Promise.all([
        User.countDocuments({ role: 'user' }),
        FileUpload.countDocuments(),

        // Active users based on actual activity (uploads OR analyses in last 30 days)
        User.aggregate([
            { $match: { role: 'user' } },
            {
                $lookup: {
                    from: 'fileuploads',
                    let: { userId: '$_id' },
                    pipeline: [
                        {
                            $match: {
                                $expr: { $eq: ['$userId', '$$userId'] },
                                createdAt: { $gte: thirtyDaysAgo }
                            }
                        },
                        { $limit: 1 }
                    ],
                    as: 'recentUploads'
                }
            },
            {
                $lookup: {
                    from: 'analyses',
                    let: { userId: '$_id' },
                    pipeline: [
                        {
                            $match: {
                                $expr: { $eq: ['$userId', '$$userId'] },
                                createdAt: { $gte: thirtyDaysAgo }
                            }
                        },
                        { $limit: 1 }
                    ],
                    as: 'recentAnalyses'
                }
            },
            {
                $match: {
                    $or: [
                        { 'recentUploads.0': { $exists: true } },
                        { 'recentAnalyses.0': { $exists: true } }
                    ]
                }
            },
            { $count: 'activeUsers' }
        ]).then(result => result.length > 0 ? result[0].activeUsers : 0),

        // Peak Upload Time - Most active hour
        FileUpload.aggregate([
            {
                $match: {
                    createdAt: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) }
                }
            },
            {
                $group: {
                    _id: { hour: { $hour: "$createdAt" } },
                    count: { $sum: 1 }
                }
            },
            { $sort: { count: -1 } },
            { $limit: 1 },
            {
                $project: {
                    hour: "$_id.hour",
                    count: 1,
                    _id: 0
                }
            }
        ])
    ]);

    // Convert hour to AM/PM format
    const formatHour = (hour) => {
        if (hour === null || hour === undefined) return 'No data';
        const period = hour >= 12 ? 'PM' : 'AM';
        const displayHour = hour === 0 ? 12 : hour > 12 ? hour - 12 : hour;
        return `${displayHour}:00 ${period}`;
    };

    // Peak upload time
    const peakHour = peakUploadTime.length > 0 ? peakUploadTime[0].hour : null;

    return {
        uploadFrequency: parseFloat((totalUploads / totalUsers).toFixed(2)),
        peakUploadTime: formatHour(peakHour),
        usageRate: parseFloat(((activeUsers / totalUsers) * 100).toFixed(2))
    };
};