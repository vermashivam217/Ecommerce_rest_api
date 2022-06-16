import Joi from "joi"
import { User, RefreshToken } from "../../models"
import CustomErrorHandler from "../../services/CustomErrorHandler"
import bcrypt from 'bcrypt'
import JwtService from '../../services/JwtService'
import { REFRESH_SECRET } from '../../config'

const loginController = {
    async login(req, res, next) {

        // Validation
        const loginSchema = Joi.object({
            email: Joi.string().email().required(),
            password: Joi.string().pattern(new RegExp('^[a-zA-Z0-9]{3,30}$')).required()
        })
        const { error } = loginSchema.validate(req.body)
        if (error) {
            return next(error)
        }
        
        try {
            const user = await User.findOne({ email: req.body.email })
            if (!user) {
                return next(CustomErrorHandler.wrongCredentials())
            }

            // Compare the password
            const match = await bcrypt.compare(req.body.password, user.password)
            if(!match) {
                return next(CustomErrorHandler.wrongCredentials())
            }

            // generating token
            const accessToken = JwtService.sign({ _id: user._id, role: user.role })
            const refresh_Token = JwtService.sign({ _id: user._id, role: user.role }, '1y', REFRESH_SECRET)

            // Database whitelist
            await RefreshToken.create({ token: refresh_Token });
            res.json({ accessToken, refresh_Token })

        } catch (error) {
            return next(error)
        }
    },
    async logout(req, res, next) {
        // Validation
        const refreshSchema = Joi.object({
            refresh_token: Joi.string().required(),
        });
        const { error } = refreshSchema.validate(req.body);

        if (error) {
            return next(error);
        }
        try {
            await RefreshToken.deleteOne({ token: req.body.refresh_token })
        } catch (error) {
            return next(new Error('Something went wrong in the database'))
        }
        res.json({ status: 1 })
    }
}



export default loginController