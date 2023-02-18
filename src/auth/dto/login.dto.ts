import { IsNotEmpty, IsString, MinLength, MaxLength, Matches } from "class-validator";

export class LoginDto {
    @IsString()
    @IsNotEmpty()
    username: string;

    @IsString()
    @IsNotEmpty()
    @MinLength(8)
    @MaxLength(20)
    @Matches(/((?=.*\d)|(?=.*\W+))(?![.\n])(?=.*[A-Z])(?=.*[a-z]).*$/, 
    { message: 'password must contain uppercase, lowercase, number and special character'})
    password:string;
}