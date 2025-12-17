import Joi from 'joi';
import { IChangePasswordRequestBody, IForgotPasswordRequestBody, ILoginRequestBody, IRegisterRequestBody, IResetPasswordRequestBody } from "../types/userTypes";



export const validateRegistorBody = Joi.object<IRegisterRequestBody, true> ({
    name: Joi.string().min(2).max(72).trim().required(),
    emailAddress:Joi.string().email().required(),
    phoneNumber: Joi.string().min(4).max(20).required(),
    password: Joi.string().min(3).max(24).required(),
    consent: Joi.boolean().valid(true).required()
})

export const validateLoginBody = Joi.object<ILoginRequestBody , true> ({
    emailAddress:Joi.string().email().trim().required(),
    password: Joi.string().min(3).max(24).required()
})

export const validateForgotBody = Joi.object<IForgotPasswordRequestBody, true> ({
    emailAddress:Joi.string().email().trim().required()
})
export const validateResetBody = Joi.object<IResetPasswordRequestBody, true> ({
   newPassword:Joi.string().min(3).max(24).trim().required()
})

export const validateChangePasswordBody = Joi.object<IChangePasswordRequestBody, true> ({
  oldPassword:Joi.string().min(3).max(24).trim().required(),
  newPassword:Joi.string().min(3).max(24).trim().required(),
  confirmNewPassword:Joi.string().min(3).max(24).trim().valid(Joi.ref('newPassword')).required()
})

export const validateJoiSchema = <T>(Schema: Joi.Schema, value:unknown) => {
    const result = Schema.validate(value)

    return {
        value: result.value as T,
        error: result.error
    }
}



