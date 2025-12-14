import { getTimezonesForCountry } from 'countries-and-timezones'
import { parsePhoneNumberWithError } from 'libphonenumber-js'
import bcrypt from 'bcrypt'
import {v4} from 'uuid'
import { randomInt } from 'crypto'


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
}
}