import Joi from 'joi';
import { ILoginRequestBody, IRegisterRequestBody } from "../types/userTypes";



export const validateRegistorBody = Joi.object<IRegisterRequestBody, true> ({
    name: Joi.string().min(2).max(72).trim().required(),
    emailAddress:Joi.string().email().required(),
    phoneNumber: Joi.string().min(4).max(20).required(),
    password: Joi.string().min(3).max(24).required(),
    consent: Joi.boolean().valid(true).required()
})

export const validateLoginBody = Joi.object<ILoginRequestBody , true> ({
    emailAddress:Joi.string().email().required(),
    password: Joi.string().min(3).max(24).required()
})

export const validateJoiSchema = <T>(Schema: Joi.Schema, value:unknown) => {
    const result = Schema.validate(value)

    return {
        value: result.value as T,
        error: result.error
    }
}

