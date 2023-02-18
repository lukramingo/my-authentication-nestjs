import { ConflictException, Injectable, NotFoundException, UnauthorizedException } from '@nestjs/common';
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
            throw new ConflictException("user already exist!");
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

        await this.mailerService.sendVerificationEmail(email, vToken);

       return {message: "successfully"}

    }

    async findUser(verification_token){

        const found = await this.userRepository.createQueryBuilder('user')
        .where('user.verification_token = :verification_token', {verification_token})
        .getOne();

        if(found.status === "1"){
            throw new ConflictException('user already verify');
        }

        if(found){
             await this.userRepository.createQueryBuilder()
            .update(User)
            .set({ status: "1" })
            .where({id: found.id})
            .execute();  
            return {message: "successfully verify user"}          
        }else{
            throw new NotFoundException('user not found');
        }        
    }

    async findEmail(email: string){

        const user = await this.userRepository.findOneBy({email});

        if(!user){
            throw new NotFoundException(`${user} not found!`);
        }

        const newToken = uuidv4()
        user.password_reset_token = newToken;
        await this.userRepository.save(user);

        await this.mailerPwdService.sendVerificationEmail(email, newToken);

        return {message: "email found"}
        
    }

    async setPassword(resetPasswordDto: ResetPasswordDto){

        const {token, newPassword} = resetPasswordDto;
        
        const user = await this.userRepository.findOneBy({password_reset_token: token});
        if(!user){
            throw new UnauthorizedException('invalid token');
        }

        const salt = await bcrypt.genSalt();
        const newPasswordHash = await bcrypt.hash(newPassword, salt);

        user.password_hash = newPasswordHash;
        return this.userRepository.save(user);
    }

    async signIn(body:LoginDto): Promise<{accessToken: string}>{
        const {username, password} = body;
        const [user] = await this.userRepository.findBy({username})
        
        if(!user){
            throw new NotFoundException(`${user} not found`);
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
