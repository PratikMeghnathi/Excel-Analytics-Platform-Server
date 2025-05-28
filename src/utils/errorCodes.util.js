export const errorCodes = {
    badRequest: 'BAD_REQUEST',
    unauthorized: 'UNAUTHORIZED',
    forbidden: 'FORBIDDEN',
    notFound: 'NOT_FOUND',
    conflict: 'CONFLICT',
    tooManyRequests: 'TOO_MANY_REQUESTS',
    serverError: 'SERVER_ERROR',
    serviceUnavailable: 'SERVICE_UNAVAILABLE',
    badGateway: 'BAD_GATEWAY',
    gatewayTimeout: 'GATEWAY_TIMEOUT',

    // Token-related
    tokenExpired: 'TOKEN_EXPIRED',
    tokenInvalid: 'TOKEN_INVALID',
    tokenTampered: 'TOKEN_TAMPERED',
    tokenMissing: 'TOKEN_MISSING',

    //other
    wrongType: 'WRONG_TYPE',
    limitFileSize: 'LIMIT_FILE_SIZE',
}
