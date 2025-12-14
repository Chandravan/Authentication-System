export default {
    SUCCESS: `The operation has been succesful`,
    SOMETHING_WENT_WRONG: `Something went wrong`,
    NOT_Found: (entity: string) => `${entity} not found`,
    INVALID_PHONE_NUMBER: `Invalid phone number`,
    ALREADY_EXIST: (entity: string, identifier: string) => {
        return `${entity} is already exist with ${identifier} `
    }
}
