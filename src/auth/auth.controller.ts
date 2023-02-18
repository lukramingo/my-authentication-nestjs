import { Body, Controller, Post, Query, Get, Param } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthCredentialDto } from './dto/auth.dto';
import { LoginDto } from './dto/login.dto';
import { EmailDto } from './dto/search-email.dto';

@Controller('auth')
export class AuthController {
    constructor(private authService: AuthService){}

    @Post('/signup')
    signUp(@Body() body: AuthCredentialDto): Promise<void>{
        return this.authService.signup(body);
    }

    @Post('/verify')
    verifyUser(@Query('token') token:string){
        return this.authService.findUser(token);
    }

    @Post('/search')
    findEmail(@Query('email') emailDto: EmailDto){
        return this.authService.findEmail(emailDto);
    }

    @Post('/reset')
    setPassword(
        @Query('token') token: string,
        @Body('newPassword') newPassword: string
        ){
        return this.authService.setPassword(token, newPassword);
    }

    @Post('/login')
    login(@Body() body:LoginDto ): Promise<{accessToken: string}>{
        return this.authService.signIn(body);
    }

}
