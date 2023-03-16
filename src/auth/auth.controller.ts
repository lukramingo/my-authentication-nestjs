import { Body, Controller, Post, Query, UseInterceptors, ClassSerializerInterceptor, Res } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthCredentialDto } from './dto/auth.dto';
import { LoginDto } from './dto/login.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { EmailDto } from './dto/search-email.dto';
import { OtpDto } from './dto/opt.dto';
import { Response } from 'express';

@UseInterceptors(ClassSerializerInterceptor)
@Controller('auth')
export class AuthController {
    constructor(private authService: AuthService){}

    @Post('/signup')
    async signUp(@Body() body: AuthCredentialDto): Promise<any>{
        return await this.authService.signup(body);
    }

    @Post('/verify')
    async verifyUser(@Body() body: OtpDto,@Res({passthrough: true}) res: Response){
        const respon = await this.authService.findUser(body);
        if(!respon){
            res.status(400).send();
        }
        return respon;
    }

    @Post('/search')
    async findEmail(@Query('email') email: EmailDto){
        return await this.authService.findEmail(email);
    }

    @Post('/reset')
    async setPassword(@Body() resetPasswordDto: ResetPasswordDto){
        return await this.authService.setPassword(resetPasswordDto);
    }

    @Post('/login')
    async login(@Body() body:LoginDto ): Promise<{accessToken: string}>{
        return await this.authService.signIn(body);
    }

}
