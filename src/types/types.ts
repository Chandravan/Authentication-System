export type tHttpResponse = {
    success: boolean
    statusCode: number
    request: {
        ip?: string | null
        method: string
        url: string
    }
    mesage: string
    data: unknown
}

export type tHttpError = {
    success: boolean
    statusCode: number
    request: {
        ip?: string | null
        method: string
        url: string
    }
    mesage: string

    data: unknown
    trace?: object | null
}
