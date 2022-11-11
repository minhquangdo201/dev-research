import { Prop, Schema, SchemaFactory } from "@nestjs/mongoose";
import { UserInterface } from "./user.interface";
import { Document } from 'mongoose';

@Schema()
export class User extends Document implements UserInterface {
    @Prop({required: true})
    userName: string;

    @Prop({required: true})
    password: string;
}

export const UserSchema = SchemaFactory.createForClass(User);