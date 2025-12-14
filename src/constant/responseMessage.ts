export default {
    SUCCESS: `The operation has been succesful`,
    SOMETHING_WENT_WRONG: `Something went wrong`,
    NOT_Found: (entity: string) => `${entity} not found`,
    INVALID_PHONE_NUMBER: `Invalid phone number`,
    ALREADY_EXIST: (entity: string, identifier: string) => {
        return `${entity} is already exist with ${identifier} `
    },
    INVALID_ACCOUNT_CONFIRMATION_TOKEN_OR_CODE: `Invalid accout confirmation or code `,
    ACCOUNT_ALREADY_CONFIRMED: `Account alredy confirm`
}
