import { NextFunction, Request, Response } from 'express'
import httpResponse from '../util/httpResponse'
import responseMessage from '../constant/responseMessage'
import httpError from '../util/httpError'
import { ILoginRequestBody, IRefreshToken, IRegisterRequestBody, IUser } from '../types/userTypes'
import { validateJoiSchema, validateLoginBody, validateRegistorBody } from '../service/validationService'
import quicker from '../util/quicker'


import databaseService from '../service/databaseService'
import { EUserRole } from '../constant/userConstant'
import config from '../config/config'
import emailService from '../service/emailService'
import logger from '../util/logger'
import dayjs from 'dayjs'
import utc from 'dayjs/plugin/utc'
import { EApplicationEnvironment } from '../constant/application'
import { string } from 'joi'

dayjs.extend(utc)

interface IRegisterRequest extends Request {
    body: IRegisterRequestBody
}

interface ILoginRequest extends Request {
    body:ILoginRequestBody
}

interface IConfirmRequest extends Request {
    params: {
        token: string
    }
    query : {
        code: string
    }
}

interface ISelfIdentificationRequest extends Request {
    authenticatedUser: IUser
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

    confirmation:async (req:Request, res:Response, next:NextFunction) => {
        try{
            const{params, query} = req as IConfirmRequest
            const{token} = params
            const{code} = query
            // Fectch user By Token & code 
            const user = await databaseService.findUserByConfirmationTokenAndCode(token, code)
            if(!user){
              return  httpError(next, new Error(responseMessage.INVALID_ACCOUNT_CONFIRMATION_TOKEN_OR_CODE) , req, 400 )
            }
            // Check if Account alredy confirm

            if(user.accountConfirmation.status){
                return httpError(next, new Error(responseMessage.ACCOUNT_ALREADY_CONFIRMED), req, 500)
            }
            // Account confirm
            user.accountConfirmation.status= true
            user.accountConfirmation.timestamp= dayjs().utc().toDate()

            await user.save()


            // Account confirmation mail send 
               
            const to = [user.emailAddress]
             const subject= 'Account confirmed'
            const text = `Hey ${user.name}, your account has been confirmed `
            
            emailService.sendEmail(to, subject, text).catch((err) => {
                logger.error('EMAIL_SERVICE', {
                    meta:err
                })
            })
            httpResponse(req , res ,200, responseMessage.SUCCESS)
        } catch (err) {
            httpError (next, err, req, 500)
        }
    },
    

    login : async(req:Request,res:Response, next:NextFunction) => {
        try{
            //todo:
            const {body} = req as ILoginRequest

            // valiate and parse body 
            const {error, value} = validateJoiSchema<ILoginRequestBody>(validateLoginBody, body)
            if (error){
                return httpError(next, error ,req, 422)
            }
            
            const {emailAddress, password} = value
            // find user 
            const user = await databaseService.findUserByEmailAddress(emailAddress, `+password`)
            if(!user) {
                return httpError(next, new Error(responseMessage.NOT_Found('user')), req, 404)
            }
            // validate password
                
            const isValidPassword = await quicker.comparePassword(password, user.password)
            if (!isValidPassword){
                return  httpError(next ,new Error(responseMessage.INVALID_EMAIL_OR_PASSWORD), req,400)
            }


            // Acces Token and Refersh Token 

            const accessToken = quicker.generateToken({
                userId: user.id
            }, config.ACCESS_TOKEN.ACCESS_TOKEN_SECRET as string,
             config.ACCESS_TOKEN.EXPIRY 
            )

            const refereshToken = quicker.generateToken({
                userId: user.id
            },
            config.REFRESH_TOKEN.REFRESH_TOKEN_SECRET as string,
            config.REFRESH_TOKEN.EXPIRY
            )
           //console.log(accessToken, refereshToken)

            // last login Information
            user.lastLoginAt = dayjs().utc().toDate()
            await user.save()


            // Refresh Token store 
            const refreshTokenPayload: IRefreshToken = {
                token: refereshToken
            }
            await databaseService.createRefreshToken(refreshTokenPayload)


            // cookie Send 
           

            const DOMAIN= quicker.getDomainFromUrl(config.SERVER_URL as  string)
            res.cookie('accessToken', accessToken, {
                path: '/api/v1',
                domain: DOMAIN,
                sameSite: 'strict',
                maxAge: 1000 * config.ACCESS_TOKEN.EXPIRY,
                httpOnly:true,
                secure: !(config.ENV== EApplicationEnvironment.DEVELOPMENT)
            }). cookie('refreshToken', refereshToken, {
                path: '/api/v1',
                domain: DOMAIN,
                sameSite: 'strict',
                maxAge: 1000 * config.REFRESH_TOKEN.EXPIRY,
                httpOnly:true,
                secure: !(config.ENV== EApplicationEnvironment.DEVELOPMENT)
            })


            httpResponse(req, res, 200 , responseMessage.SUCCESS)

        } catch (err){
            httpError(next, err, req,500)

        }
    },

    selfIdentification:(req:Request, res:Response, next:NextFunction) => {
        try{
            const {authenticatedUser} = req as ISelfIdentificationRequest
            httpResponse(req, res,200, responseMessage.SUCCESS, authenticatedUser )
        } catch(err){
            httpError(next, err, req ,500)
        }
    },

    logout:async(req: Request, res:Response, next:NextFunction) => {
        try{
            const {cookies}= req 
            const { refreshToken} = cookies as {
                refreshToken: string | undefined
            }

            if(refreshToken){
                // call db -> to delete the refresh token
                await databaseService.deleteRefreshToken(refreshToken)
            }
            const DOMAIN= quicker.getDomainFromUrl(config.SERVER_URL as  string)

            //cookies clear
            res.clearCookie('accessToken', {
                 path: '/api/v1',
                domain: DOMAIN,
                sameSite: 'strict',
                maxAge: 1000 * config.ACCESS_TOKEN.EXPIRY,
                httpOnly:true,
                secure: !(config.ENV== EApplicationEnvironment.DEVELOPMENT)
            })

            res.clearCookie('refreshToken', {
                path: '/api/v1',
                domain: DOMAIN,
                sameSite: 'strict',
                maxAge: 1000 * config.REFRESH_TOKEN.EXPIRY,
                httpOnly:true,
                secure: !(config.ENV== EApplicationEnvironment.DEVELOPMENT)
            })
            httpResponse(req,res,  200, responseMessage.SUCCESS)

        }catch(err){
            httpError(next, err, req, 500)

        }

    }


}
