export const createError = (code, key, errormsg) => {
    return {
        code: code,
        errors: {
            [key]: {
                message: errormsg,
                path: key,
            },
        },
    };
};