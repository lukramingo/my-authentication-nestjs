import { BadRequestException, ConflictException, Injectable, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
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
import { OtpStore } from './entity/otp.entity';
import { OtpDto } from './dto/opt.dto';
import * as crypto from 'crypto';

@Injectable()
export class AuthService {
    constructor(
        @InjectRepository(User) private userRepository: Repository<User>,
        @InjectRepository(OtpStore) private optRepository: Repository<OtpStore>,
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
        
        await this.userRepository.save(user)

        //otp 4 digit number generate
        let otp = crypto.randomInt(10000, 99999).toString();   

        const optStore = new OtpStore()
        optStore.otp = otp;
        optStore.userId = user.id;

        
        await this.optRepository.save(optStore)
     

        await this.mailerService.sendVerificationEmail(email, vToken, otp);

       return {message: "signup verify link has send to email"};

    }


    async findUser({token, otp}: OtpDto){
        
        const user = await this.userRepository.findOneBy({verification_token: token});

        if(!user){
            throw new NotFoundException('User not found. Please try again.');
        }

        if(user.status === "1"){
            throw new ConflictException('user already verify');
        }
        
        //check user token expired time
        let myEpochCurrent = Math.floor(new Date().getTime());
        // let myExpiredDate = moment(user.created_at).add(2, 'minutes').toDate();
        // let myEpochExpired = Math.floor(myExpiredDate.getTime());


        // if(myEpochExpired < myEpochCurrent){
        //     throw new BadRequestException('user token has expired');
        // }

        // select record has userId and latest id from otp record
        const found = await this.optRepository.createQueryBuilder('OtpStore')
        .where({userId: user.id})
        .orderBy('id', 'DESC')
        .getOne();
        
        if(found.status === '1'){
            throw new Error('otp already varify');
        }

        if(!found || (found.otp !== otp)){
            throw new BadRequestException('otp invalid');
        }

        // expired time check for otp       
        let myExpiredOtp = moment(found.created_at).add(1, 'minutes').toDate();
        let myEpochExpiredOtp = Math.floor(myExpiredOtp.getTime());
        
        if(myEpochExpiredOtp < myEpochCurrent){
            throw new BadRequestException('otp has expired');
        }
        
        await this.optRepository.createQueryBuilder()
        .update(OtpStore)
        .set({status: '1'})
        .where({id: found.id})
        .execute();
        
            
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

    async findEmail({email}: EmailDto){

        const user = await this.userRepository.findOneBy({email: email});

        if(!user){
            throw new NotFoundException(`${user.email} not found!`);
        }

        const newToken = uuidv4()
        user.password_reset_token = newToken;
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
        let myEpoch = Math.floor(new Date().getTime()/1000.0);
        let myExpiredDate = moment(user.updated_at).add(1, 'minutes').toDate();
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