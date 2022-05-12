import Joi from "joi"
import { User } from '../../models';
import bcrypt from 'bcrypt';
import JwtService from "../../services/JwtService";

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

        // Hash password
        const hashedPassword = await bcrypt.hash(req.body.password, 10)

        // prepare the model 
        const { name, email, password } = req.body
        const user = {
            name,
            email,
            password: hashedPassword
        }

        let accessToken
        try {
            const result = await User.save();

            console.log(result);

            // Token
            accessToken = JwtService.sign({ _id: result._id, role: result.role })


        } catch (err) {
            return next(err)
        }


        res.json({ accessToken: accessToken})
    }
}




export default registerController 