import { Request, Response } from 'express'
import { tHttpResponse } from '../types/types'
import { EApplicationEnvironment } from '../constant/application'
import config from '../config/config'

export default (req: Request, res: Response, responseStatusCode: number, ResponseMessage: string, data: unknown = null): void => {
    const response: tHttpResponse = {
        success: true,
        statusCode: responseStatusCode,
        request: {
            ip: req.ip || null,
            method: req.method,
            url: req.originalUrl
        },
        mesage: ResponseMessage,
        data: data
    }
    //log
    // eslint-disable-next-line no-console
    console.info(`CONTROLLER_RESPONSE`, {
        meta: response
    })

    if (config.ENV == EApplicationEnvironment.PRODUCTION) {
        delete response.request.ip
    }

    res.status(responseStatusCode).json(response)
}
