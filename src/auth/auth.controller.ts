import { Body, Controller, Post, Query, Get, Param, UseInterceptors, ClassSerializerInterceptor } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthCredentialDto } from './dto/auth.dto';
import { LoginDto } from './dto/login.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { EmailDto } from './dto/search-email.dto';
import { OtpDto } from './dto/opt.dto';

@UseInterceptors(ClassSerializerInterceptor)
@Controller('auth')
export class AuthController {
    constructor(private authService: AuthService){}

    @Post('/signup')
    signUp(@Body() body: AuthCredentialDto): Promise<any>{
        return this.authService.signup(body);
    }

    @Post('/verify')
    verifyUser(@Body() body: OtpDto){
        return this.authService.findUser(body);
    }

    @Post('/search')
    findEmail(@Query('email') email: EmailDto){
        return this.authService.findEmail(email);
    }

    @Post('/reset')
    setPassword(
        @Body() resetPasswordDto: ResetPasswordDto 
        ){
        return this.authService.setPassword(resetPasswordDto);
    }

    @Post('/login')
    login(@Body() body:LoginDto ): Promise<{accessToken: string}>{
        return this.authService.signIn(body);
    }

}
