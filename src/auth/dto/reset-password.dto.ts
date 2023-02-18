import { IsNotEmpty, IsString } from "class-validator";

export class ResetPasswordDto {
    @IsString()
    token: string;

    @IsString()
    @IsNotEmpty()
    newPassword: string;

}