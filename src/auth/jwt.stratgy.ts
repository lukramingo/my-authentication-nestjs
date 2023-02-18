import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { jwtContants } from './constants';
import { JwtPayload } from './jwt-payload.interface';
import { AuthService } from './auth.service';
import { User } from './entity/user.entity';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private authService: AuthService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: jwtContants.secret,
    });
  }

  async validate(payload: JwtPayload): Promise<User> {
    const {username} = payload;
    const user = await this.authService.findByUsername(username);

    if(!user){
        throw new UnauthorizedException()
    }
    return user;
  }
}