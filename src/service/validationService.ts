import Joi from 'joi';
import { IRegisterRequestBody } from "../types/userTypes";



export const validateRegistorBody = Joi.object<IRegisterRequestBody> ({
    name: Joi.string().min(2).max(72).trim().required(),
    emailAddress:Joi.string().email().required(),
    phoneNumber: Joi.string().min(4).max(20).required(),
    password: Joi.string().min(3).max(24).required(),
    consent: Joi.boolean().valid(true).required()
})

export const validateJoiSchema = <T>(Schema: Joi.Schema, value:unknown) => {
    const result = Schema.validate(value)

    return {
        value: result.value as T,
        error: result.error
    }
}