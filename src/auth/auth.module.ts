import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { User } from './entity/user.entity';
import { MailerService } from '../mailer/mailer.service';
import { MailerPwdService } from '../mailerPwd/mailer-pwd.service';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import { jwtContants } from './constants';
import { JwtStrategy } from './jwt.stratgy';

@Module({
  imports:[
    PassportModule.register({defaultStrategy: 'jwt'}),
    JwtModule.register({
      secret: jwtContants.secret,
      signOptions: {expiresIn: '60m'}
    }),
    TypeOrmModule.forFeature([User])
  ],
  controllers: [AuthController],
  providers: [AuthService, MailerService, MailerPwdService, JwtStrategy],
  exports: [JwtStrategy, PassportModule]
})
export class AuthModule {}
