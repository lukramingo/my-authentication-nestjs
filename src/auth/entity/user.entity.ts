import { Exclude } from "class-transformer";
import { Column, CreateDateColumn, Entity, PrimaryGeneratedColumn, UpdateDateColumn } from "typeorm";

@Entity()
export class User {
    @PrimaryGeneratedColumn()
    id: number;

    @Column({type: 'varchar', length: 255, unique: true})
    username: string;

    @Column({type: 'varchar', length: 255, unique: true})
    email: string;

    @Column({type: 'varchar', length: 255})
    @Exclude()
    password_hash: string;

    @Column({type: 'char', length:1, default: '2'})
    status: string;

    @Column({type: 'varchar', length: 255, default: null})
    @Exclude()
    verification_token: string;

    @Column({type: 'varchar', length: 255, default: null})
    @Exclude()
    password_reset_token: string;

    @CreateDateColumn({type: 'timestamp'})
    created_at: Date;

    @UpdateDateColumn({type: 'timestamp', nullable: true, default: null})
    updated_at: Date;
}