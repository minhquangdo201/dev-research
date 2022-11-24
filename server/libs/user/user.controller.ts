import { Body, Controller, Get, Post, Req } from "@nestjs/common";
import { LoginUserDto } from "./dto/user.dto";
import { UserInterface } from "./user.interface";
import { UserService } from "./user.service";

@Controller('user')
export class UserController {
    constructor(private userService: UserService){}
    
    @Get('getUser')
    async getAll(){
        return await this.userService.getAll();
    }

    @Post('postUser')
    async addUser(@Req() req): Promise<UserInterface>{
        return this.userService.addUser(req.body);
    }

    @Post('login')
    async login(@Body() loginUserDto: LoginUserDto): Promise<UserInterface>{
        return this.userService.login(loginUserDto)
    }
}
