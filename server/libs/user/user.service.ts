import { HttpException, HttpStatus, Injectable } from "@nestjs/common";
import { InjectModel } from "@nestjs/mongoose";
import { Model } from "mongoose";
import { async } from "rxjs";
import { LoginUserDto } from "./dto/user.dto";
import { UserInterface } from "./user.interface";
import { User } from "./user.schema";

@Injectable()
export class UserService {
    constructor(
        @InjectModel(User.name) private userModal: Model<User>
    ) { }

    async getAll(): Promise<UserInterface[]> {
        return this.userModal.find().exec();
    }

    async addUser(user: UserInterface): Promise<UserInterface> {
        const u = new this.userModal(user);
        return u.save()
    }

    async findByUserName (userName: string): Promise<User | undefined> {
        return this.userModal.findOne( {userName: userName} )
    }

    async login(user: LoginUserDto): Promise<any>{
        const u = await this.findByUserName(user.userName)
        if(!u){
            throw new HttpException('Not found',HttpStatus.NOT_FOUND)
        }
        if(user.password !== u.password){
            throw new HttpException('Invalid'+user.password, HttpStatus.UNAUTHORIZED)
        }
        return u
    }
}