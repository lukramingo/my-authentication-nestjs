import { BadRequestException, ConflictException, Injectable, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, DataSource } from 'typeorm';
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
import {request, response} from 'express';

@Injectable()
export class AuthService {
    constructor(
        @InjectRepository(User) private userRepository: Repository<User>,
        @InjectRepository(OtpStore) private optRepository: Repository<OtpStore>,
        private mailerService: MailerService,
        private mailerPwdService: MailerPwdService,
        private jwtService: JwtService,
        private dataSource: DataSource
        ){}
        
    async signup({username, email, password}: AuthCredentialDto): Promise<any>{

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

        // generate random otp 6 digit number
        let otpCode = crypto.randomInt(10000, 99999).toString();  

        const queryRunner = this.dataSource.createQueryRunner();
        await queryRunner.connect();
        await queryRunner.startTransaction();

        try{


            if(await queryRunner.manager.save(user)){ 
    
                const optStore = new OtpStore()
                optStore.otp = otpCode;
                optStore.userId = user.id;        
                
                if(!await queryRunner.manager.save(optStore)){
                    await queryRunner.rollbackTransaction();
                    throw new BadRequestException('400');
                }
               
            }else{
                await queryRunner.rollbackTransaction();
                throw new BadRequestException('400');
            }

            await queryRunner.commitTransaction();

            await this.mailerService.sendVerificationEmail(email, vToken, otpCode);
            
           return {message: "signup verify link has send to email"};

        }catch(err){
            await queryRunner.rollbackTransaction();
        }finally{
            await queryRunner.release();
        }
       
    }


    async findUser({token, otp}: OtpDto): Promise<any>{

        const user = await this.userRepository.findOneBy({verification_token: token});
         
        if(!user){
            throw new NotFoundException('User not found. Please try again.');
        }
        
        if(user.status === "1"){
            throw new ConflictException('user already verify');
        }        

        const foundLatest = await this.optRepository.createQueryBuilder('OtpStore')
        .where({userId: user.id})
        .orderBy('id', 'DESC')
        .getOne();

        // console.log(foundLatest);

        if(!foundLatest || foundLatest.status === '1' || (foundLatest.otp !== otp)){

            throw new BadRequestException('otp invalid');
        }

        // expired time check for otp 
        let myEpochCurrent = Math.floor(new Date().getTime());      
        let myExpiredOtp = moment(foundLatest.created_at).add(30, 'minutes').toDate();
        let myEpochExpiredOtp = Math.floor(myExpiredOtp.getTime());

        if(myEpochExpiredOtp < myEpochCurrent){
            throw new BadRequestException('otp has expired')
        }
           
        
        const queryRunner = this.dataSource.createQueryRunner();
        await queryRunner.connect();
        await queryRunner.startTransaction();
        
        try{

        if(await queryRunner.manager.createQueryBuilder()
        .update(OtpStore)
        .set({status: '1'})
        .where({id: foundLatest.id})
        .execute()){           
           
            if(user.status === "2"){
                
                user.status = "1";
                
                if(!await queryRunner.manager.save(user)){                 
                    await queryRunner.rollbackTransaction();
                    throw new BadRequestException('error fail to update user status');
                }
            
            }else{
                throw new NotFoundException('Invalid user');           
            }

        }else{
            await queryRunner.rollbackTransaction();
            throw new BadRequestException('otp status failed to updated');
        }

        await queryRunner.commitTransaction();
        return {message: "sucessfully varify"};
            
    }catch(err){
        await queryRunner.rollbackTransaction();
    }finally{
        await queryRunner.release();
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

        if(!(myEpoch < myEpochExp)){
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