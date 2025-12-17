import { getTimezonesForCountry } from 'countries-and-timezones'
import { parsePhoneNumberWithError } from 'libphonenumber-js'
import bcrypt from 'bcrypt'
import {v4} from 'uuid'
import { randomInt, verify } from 'crypto'
import jwt, { TokenExpiredError } from 'jsonwebtoken';
import dayjs from 'dayjs'



export default { 
    parsePhoneNumber: (PhoneNumber: string) => {
    try {
        const parsedPhoneNumber = parsePhoneNumberWithError(PhoneNumber)
        if (parsedPhoneNumber){
            return{
                countryCode: parsedPhoneNumber.countryCallingCode,
                isoCode: parsedPhoneNumber.country || null ,
                internationalNumber: parsedPhoneNumber.formatInternational()
            }
        }
         return{
                countryCode: null,
                isoCode: null ,
                internationalNumber:null
            }
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    } catch (err){
         return{
                countryCode: null,
                isoCode: null ,
                internationalNumber:null
            }
                
    }
},

countryTimezone: (isoCode: string) => {
    return getTimezonesForCountry(isoCode)
},

hashPassword: (password: string): Promise<string> => {
    return  bcrypt.hash(password, 10)
},
generateRandomId: () => v4(),
generateOtp: (length: number) => {
    const min = Math.pow(10, length-1)
    const max = Math.pow(10, length)-1

    return randomInt(min, max).toString()
},

comparePassword: (newPassword: string, encryptedPassword: string) => {
    return bcrypt.compare(newPassword, encryptedPassword)
},

generateToken: ( payload: object, secret:string, expiry:number) => {
  return jwt.sign(payload, secret, {
    expiresIn: expiry
  })
},

verifyToken: (Token:string, ACCESS_TOKEN_SECRET:string) => {
    return jwt.verify(Token, ACCESS_TOKEN_SECRET)
},
getDomainFromUrl:( url: string) => {
     try {
                    const parsedUrl = new URL(url)
                  return   parsedUrl.hostname
                } catch (err){
                    throw err
                }
},

generateResetPasswordExpiry: (minute: number) => {
    return dayjs().valueOf() + minute*60*1000 
}
}