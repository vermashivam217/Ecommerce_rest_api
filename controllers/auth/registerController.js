import Joi from "joi"
import { User, RefreshToken } from '../../models';
import bcrypt from 'bcrypt';
import JwtService from "../../services/JwtService";
import CustomErrorHandler from "../../services/CustomErrorHandler"
import { REFRESH_SECRET } from "../../config"

const registerController = {
    async register(req, res, next) {

        // Validation
        const registerSchema = Joi.object({
            name: Joi.string().min(3).max(30).required(),
            email: Joi.string().email().required(),
            password: Joi.string().pattern(new RegExp('^[a-zA-Z0-9]{3,30}$')).required(),
            repeat_password: Joi.ref('password')
        })


        const { error } = registerSchema.validate(req.body)
        if (error) {
            return next(error)
        }
        
        // check if user is in the database already 
        try {
            const exist = await User.exists({ email: req.body.email });
            if (exist) {
                return next(CustomErrorHandler.alreadyExist('This email is already taken.'));
            }
        } catch(err) {
            return next(err)
        }
        const { name, email, password } = req.body

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10)

        // prepare the model 
        
        const user = new User ({
            name,
            email,
            password: hashedPassword
        });

        let access_Token
        let refresh_Token
        try {
            const result = await user.save();

            console.log(result);

            // Token
            access_Token = JwtService.sign({ _id: result._id, role: result.role })
            refresh_Token = JwtService.sign({ _id: result._id, role: result.role }, '1y', REFRESH_SECRET)

            // Database whitelist
            await RefreshToken.create({ token: refresh_Token });


        } catch (err) {
            return next(err)
        }


        res.json({ access_Token, refresh_Token})
    }
}




export default registerController 