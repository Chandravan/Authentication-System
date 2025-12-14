import dotenvFlow from 'dotenv-flow'

dotenvFlow.config()

export default {
    ENV: process.env.ENV,
    PORT: process.env.PORT,
    SERVER_URL: process.env.SERVER_URL,

    DATABASE_URL: process.env.DATABASE_URL,

    // Frontded
     FRONTEND_URL: process.env.FRONTEND_URL,

    // Email Service

    EMAIL_SERVICE_API_KEY: process.env.EMAIL_SERVICE_API_KEY
}
