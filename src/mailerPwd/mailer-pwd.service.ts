import { Injectable } from '@nestjs/common';
import * as nodemailer from 'nodemailer';

@Injectable()
export class MailerPwdService {
  async sendVerificationEmail(to: string, token: string): Promise<void> {
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: 'lukramingo2017@gmail.com',
        pass: 'womadvqotfjgwdfz',
      },
    });

    const verificationLink = `http://localhost:3000/auth/reset?token=${token}`;

    const mailOptions = {
      from: 'lukramingo2017@gmail.com',
      to,
      subject: 'Verify your reset password link',
      html: `Click <a href="${verificationLink}">here</a>`,
    };

    return await transporter.sendMail(mailOptions);
  }
}
