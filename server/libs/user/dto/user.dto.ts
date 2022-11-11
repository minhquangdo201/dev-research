import { UserInterface } from "../user.interface";

export class LoginUserDto extends UserInterface {
    readonly userName: string;
    readonly password: string;
}