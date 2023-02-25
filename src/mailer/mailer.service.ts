import { Injectable } from '@nestjs/common';
import * as nodemailer from 'nodemailer';

@Injectable()
export class MailerService {
  async sendVerificationEmail(to: string, token: string, otp: string): Promise<void> {
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: 'lukramingo2017@gmail.com',
        pass: 'womadvqotfjgwdfz',
      },
    });

    const verificationLink = `http://localhost:3000/auth/verify?token=${token}`;

    const mailOptions = {
      from: 'lukramingo2017@gmail.com',
      to,
      subject: 'Verify your email',
      html: `Click <a href="${verificationLink}">here</a> OTP:${otp} token:${token} to verify your email`,
    };

    try{
      return await transporter.sendMail(mailOptions);
      
    }catch(err){
      throw new Error('try again');
    }
  }
}