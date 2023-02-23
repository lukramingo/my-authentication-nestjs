import { TypeOrmModuleOptions } from "@nestjs/typeorm";
import { OtpStore } from "../auth/entity/otp.entity";
import { User } from "../auth/entity/user.entity";

export const typeOrmConfig: TypeOrmModuleOptions = {
    type: 'mysql',
    host: 'localhost',
    port: 3306,
    username: 'root',
    password: 'Nature@2022',
    database: 'myauth_db',
    entities: [User, OtpStore],
    synchronize: true
}