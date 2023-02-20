import { BadRequestException, ConflictException, Injectable, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { LessThan, LessThanOrEqual, MoreThan, Repository } from 'typeorm';
import { AuthCredentialDto } from './dto/auth.dto';
import { User } from './entity/user.entity';
import * as bcrypt from 'bcrypt';
import { MailerService } from '../mailer/mailer.service';
import { v4 as uuidv4 } from 'uuid';
import { MailerPwdService } from '../mailerPwd/mailer-pwd.service';
import { LoginDto } from './dto/login.dto';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './jwt-payload.interface';
import { ResetPasswordDto } from './dto/reset-password.dto';
import * as moment from 'moment';
import { EmailDto } from './dto/search-email.dto';

@Injectable()
export class AuthService {
    constructor(
        @InjectRepository(User) private userRepository: Repository<User>,
        private mailerService: MailerService,
        private mailerPwdService: MailerPwdService,
        private jwtService: JwtService
        ){}
        
    async signup(body: AuthCredentialDto): Promise<any>{
        const {username, email, password} = body;

        const exitUser = await this.userRepository.findOneBy({username});
        if(exitUser){
            throw new ConflictException(`${exitUser.username} already exist!`);
        }

        const salt = await bcrypt.genSalt();
        const passwordHash = await bcrypt.hash(password, salt);

        const vToken = uuidv4();

        const user = new User();
        user.username = username;
        user.email = email;
        user.password_hash = passwordHash;
        user.verification_token = vToken;
        user.created_at = moment().add(1, 'minutes').toDate();

        await this.userRepository.save(user)

        await this.mailerService.sendVerificationEmail(email, vToken);

       return {message: "signup verify link has send to email"};

    }

    async findUser(token: string){

        const user = await this.userRepository.findOneBy({verification_token: token});

        if(!user){
            throw new NotFoundException('User not found. Please try again.');
        }
        
        //check user token expired time
        let myDate = new Date();
        let myEpochCurrent = Math.floor(myDate.getTime());
        let myExpiredDate = user.created_at;
        let myEpochExpired = Math.floor(myExpiredDate.getTime());

        console.log(myEpochCurrent);
        console.log(myEpochExpired);

        if(myEpochExpired <= myEpochCurrent){
            throw new BadRequestException('token has expired');
        }else{

            if(user.status === "1"){
                throw new ConflictException('user already verify');
            }
                
            if(user.status === "2"){
                await this.userRepository.createQueryBuilder()
                .update(User)
                .set({ status: "1" })
                .where({id: user.id})
                .execute();  
                return {message: "successfully verify user"}; 
            }else{
                throw new NotFoundException('Invalid user');           
            }      
        }

       
    }

    async findEmail({email}: EmailDto){

        const user = await this.userRepository.findOneBy({email: email});

        if(!user){
            throw new NotFoundException(`${user.email} not found!`);
        }

        const newToken = uuidv4()
        user.password_reset_token = newToken;
        user.updated_at = moment().add(10, 'minutes').toDate();
        await this.userRepository.save(user);

        await this.mailerPwdService.sendVerificationEmail(email, newToken);

        return {message: "reset password verification link has send"}
        
    }

    async setPassword(resetPasswordDto: ResetPasswordDto){

        const {token, newPassword} = resetPasswordDto;
        
        const user = await this.userRepository.findOneBy({password_reset_token: token});

        if(!user){
            throw new UnauthorizedException('invalid user');
        }
        //checking for expired password_reset_token
        let myDate = new Date();
        let myEpoch = Math.floor(myDate.getTime()/1000.0);
        let myExpiredDate = user.updated_at;
        let myEpochExp = Math.floor(myExpiredDate.getTime()/1000.0);

        if(!(myEpoch <= myEpochExp)){
            throw new BadRequestException('token has expired');
        }

        const salt = await bcrypt.genSalt();
        const newPasswordHash = await bcrypt.hash(newPassword, salt);

        user.password_hash = newPasswordHash;
        user.password_reset_token = null;
        this.userRepository.save(user);
        return {message: "successfully change password"};
    }

    async signIn(body:LoginDto): Promise<{accessToken: string}>{
        const {username, password} = body;
        const [user] = await this.userRepository.findBy({username})
        
        if(!user && user.status === "2"){
            throw new NotFoundException(`${user.username} not found or not verify`);
        }

        if(!await bcrypt.compare(password, user.password_hash)){
            throw new UnauthorizedException('Invalid password');
        }

        const payload: JwtPayload = {username};
        const accessToken = await this.jwtService.sign(payload)

        return { accessToken };
    }

    findByUsername(username:string){
        return this.userRepository.findOneBy({username});
    }
}
