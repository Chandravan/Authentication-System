import { NextFunction, Request, Response } from 'express'
import httpResponse from '../util/httpResponse'
import responseMessage from '../constant/responseMessage'
import httpError from '../util/httpError'
import { IRegisterRequestBody, IUser } from '../types/userTypes'
import { validateJoiSchema, validateRegistorBody } from '../service/validationService'
import quicker from '../util/quicker'


import databaseService from '../service/databaseService'
import { EUserRole } from '../constant/userConstant'
import config from '../config/config'
import emailService from '../service/emailService'
import logger from '../util/logger'

interface IRegisterRequest extends Request {
    body: IRegisterRequestBody
}

export default {
    self: (req: Request, res: Response, next: NextFunction) => {
        try {
            //USER
            httpResponse(req, res, 200, responseMessage.SUCCESS)
        } catch (err) {
            httpError(next, err, req, 500)
        }
    },

     register:async(req: Request, res: Response, next: NextFunction) => {
        try {
            const {body } = req as IRegisterRequest
            
            //todo:
            // BODY VALIDATION

            const { error, value} = validateJoiSchema<IRegisterRequestBody>(validateRegistorBody, body)
           
            if(error) {
                return httpError (next, error, req, 422)
            }
           
            
            // PHONE NUMBER PARSING & VALIDATING
            const {name,emailAddress,phoneNumber, password, consent} =value
           const {countryCode,internationalNumber,isoCode}= quicker.parsePhoneNumber('+' + phoneNumber)

           if (!countryCode || !internationalNumber || !isoCode) {
            return httpError (next ,new Error(responseMessage.INVALID_PHONE_NUMBER), req ,422)
           }
            
            // TIMEZONE
            const timezone = quicker.countryTimezone(isoCode)
            if (!timezone || timezone.length === 0 ) {
                return httpError(next, new Error(responseMessage.INVALID_PHONE_NUMBER), req,422)
            }
            //console.log(timezone)




            // CHECK USER EXISTENCE USING EMAIL ADDRESS 
            

             const user =await databaseService.findUserByEmailAddress(emailAddress)
             if (user){
                return  httpError(next, new Error(responseMessage.ALREADY_EXIST ('user', emailAddress)), req,422)
             }



            // ENCRYPTION PASSWORD
            const encryptedPassword= await quicker.hashPassword(password)
            // onsole.log(encryptedPassword)

            // ACCOUNT CONFIRMATION OBJECT DATA
            const token = quicker.generateRandomId()
            const code=quicker.generateOtp(6)


            // CREATING USER
            const payload:IUser ={
                name,
                emailAddress,
                phoneNumber:{
                    countryCode,
                    isoCode,
                    internationalNumber
                },
                accountConfirmation: {
                    status: false,
                    token,
                    code,
                    timestamp: null
                },
                passwordReset: {
                    token: null,
                    expiry: null,
                    lastResetAt: null
                },
                lastLoginAt: null,
                role: EUserRole.USER,
                timezone: timezone[0]!.name ,
                password: encryptedPassword,
                consent
            }


            const newUser = await databaseService.registerUser(payload)

            // SEND EMAIL
            const confirationUrl =`${config.FRONTEND_URL}/confirmation/${token}?code=${code}`
            const to = [emailAddress]
            const subject = 'confirm Your Account'
            const text = `Hey ${name}, Please confirm Your account by clicking on the link given below \n\n ${confirationUrl}  `
            
            emailService.sendEmail(to, subject, text).catch((err) => {
                logger.error('EMAIL_SERVICE', {
                    meta:err
                })
            })
            httpResponse(req, res, 201, responseMessage.SUCCESS, {_id: newUser._id})
        } catch (err) {
            httpError(next, err, req, 500)
        }
    },


}
