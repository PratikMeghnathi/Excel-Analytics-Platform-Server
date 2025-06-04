import { Analysis, FileUpload, User } from "../models/index.js";
import { createError, errorCodes } from "../utils/index.js";

export const getAdminDashboardAnalytics = async (req, res) => {
    try {
        // Check if user is admin
        if (req.user.role !== 'admin') {
            return res.status(403).json(createError(errorCodes.forbidden, 'permission', 'Access denied. Admin privileges required.'));
        }

        const now = new Date();
        const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);

        const [
            basicStats,
            userStats,
            analyticsStats
        ] = await Promise.all([
            // Basic Stats
            getBasicStats(),

            // User Stats
            getUserStats(thirtyDaysAgo),

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
        console.error('Admiini dashboard analytics error:', error);
        res.status(500).json(createError(errorCodes.serverError, 'serverError', 'An error occured while uploading and parsing excel file.'));
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
const getUserStats = async (thirtyDaysAgo) => {
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
                        cond: { $gte: ['$$upload.createdAt', thirtyDaysAgo] }
                    }
                },
                recentAnalyses: {
                    $filter: {
                        input: '$analyses',
                        as: 'analysis',
                        cond: { $gte: ['$$analysis.createdAt', thirtyDaysAgo] }
                    }
                }
            }
        },
        {
            $addFields: {
                totalRecentActivity: {
                    $add: [
                        { $size: '$recentUploads' },
                        { $size: '$recentAnalyses' }
                    ]
                },
                // Determine if user is active (has activity in last 30 days)
                isActive: {
                    $gt: [
                        {
                            $add: [
                                { $size: '$recentUploads' },
                                { $size: '$recentAnalyses' }
                            ]
                        },
                        0
                    ]
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
                // Better handle lastActivity with null checks
                lastActivity: {
                    $cond: {
                        if: {
                            $or: [
                                { $gt: [{ $size: '$uploads' }, 0] },
                                { $gt: [{ $size: '$analyses' }, 0] }
                            ]
                        },
                        then: {
                            $max: [
                                { $ifNull: [{ $max: '$uploads.createdAt' }, new Date(0)] },
                                { $ifNull: [{ $max: '$analyses.createdAt' }, new Date(0)] }
                            ]
                        },
                        else: null
                    }
                },
                uploadLimit: '$uploadLimit',
                analysisLimit: '$analysisLimit',
                totalRecentActivity: 1,
                isActive: 1,
                status: {
                    $cond: {
                        if: '$isActive',
                        then: 'Active',
                        else: 'Inactive'
                    }
                }
            }
        },
        { $sort: { totalRecentActivity: -1, lastActivity: -1 } }
    ]);

    return users;
};

// Analytics & Reporting Stats: Upload Frequency, Peak Upload Time, Usage Rate
const getAnalyticsReportingStats = async (thirtyDaysAgo) => {
    const [
        totalUsers,
        totalUploads,
        recentUploads,
        activeUsers,
        peakUploadTime
    ] = await Promise.all([
        User.countDocuments({ role: 'user' }),
        FileUpload.countDocuments({ userId: { $exists: true } }),

        // Recent uploads for consistent time period calculation
        FileUpload.countDocuments({
            userId: { $exists: true },
            createdAt: { $gte: thirtyDaysAgo }
        }),

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

        // Peak Upload Time - Most active hour (consistent 30-day period)
        FileUpload.aggregate([
            {
                $match: {
                    createdAt: { $gte: thirtyDaysAgo },
                    userId: { $exists: true }
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

    // Convert hour to AM/PM format with better error handling
    const formatHour = (hour) => {
        if (hour === null || hour === undefined) return 'No data available';
        const period = hour >= 12 ? 'PM' : 'AM';
        const displayHour = hour === 0 ? 12 : hour > 12 ? hour - 12 : hour;
        return `${displayHour}:00 ${period}`;
    };

    // Better handling of peak upload time
    const peakHour = peakUploadTime.length > 0 ? peakUploadTime[0].hour : null;
    const peakUploadCount = peakUploadTime.length > 0 ? peakUploadTime[0].count : 0;

    // Use recent uploads for frequency calculation (last 30 days)
    const uploadFrequency = totalUsers > 0 ? parseFloat((recentUploads / totalUsers).toFixed(2)) : 0;
    const usageRate = totalUsers > 0 ? parseFloat(((activeUsers / totalUsers) * 100).toFixed(2)) : 0;

    return {
        uploadFrequency, // Average uploads per user in last 30 days
        peakUploadTime: formatHour(peakHour),
        peakUploadCount, // Number of uploads during peak hour
        usageRate, // Percentage of users active in last 30 days
        totalRecentUploads: recentUploads, // Total uploads in last 30 days
        totalUploadsAllTime: totalUploads // Total uploads all time for reference
    };
};