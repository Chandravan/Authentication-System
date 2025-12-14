import { Router } from 'express'
import apiController from '../controller/apiController'

const router = Router()

router.route('/self').get(apiController.self)
router.route('/register').post(apiController.register)
router.route('/confirmation/:token').put(apiController.confirmation)

export default router
