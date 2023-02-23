import { Column, CreateDateColumn, Entity, ManyToOne, PrimaryGeneratedColumn, JoinColumn } from "typeorm";
import { User } from "./user.entity";

@Entity()
export class OtpStore {
    @PrimaryGeneratedColumn()
    id: number;

    @Column()
    otp: string;

    @Column({length:1, default: '0'})
    status: string;
    
    @CreateDateColumn({type: 'timestamp'})
    created_at: Date;

    @ManyToOne(type => User, user => user.otpStores)
    user: User;
    
    @Column()
    userId: number;

}