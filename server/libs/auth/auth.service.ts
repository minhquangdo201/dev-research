import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UserService } from 'libs/user/user.service';

@Injectable()
export class AuthService {
    constructor(private userService : UserService, private jwtService: JwtService){}

    async validateUser(userName : string, password: string): Promise<any>{
        const user = await this.userService.findByUserName(userName)
        if(user && user.password === password){
            const { password, ...result} = user
            return result
        }
        return null;
    }

    async login(user: any){
        const payload = {userName: user.userName}
        return {
            access_token: this.jwtService.sign(payload)
        }
    }
}
