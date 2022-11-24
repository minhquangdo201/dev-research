import { Body, Controller, Get, Post, Req, Request, UseGuards } from '@nestjs/common';
import { AppService } from './app.service';
import { AuthService } from 'libs/auth/auth.service';
import { AuthGuard } from '@nestjs/passport';

interface UserAnswer {
  username: string;
  answers: any
}
@Controller()
export class AppController {
  constructor(private readonly appService: AppService, private authService: AuthService) {}

  @Post('cacheAnswers')
  async saveAnswers(@Body() userAnswer: UserAnswer){
    return await this.appService.saveUserAnswer(userAnswer);
  }

  @Post('getCacheAnswers')
  async getAnswers(@Body() username) {
    return await this.appService.getUserAnswers(username)
    }
}


