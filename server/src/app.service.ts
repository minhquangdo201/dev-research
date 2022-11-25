import { CACHE_MANAGER, Inject, Injectable } from '@nestjs/common';
import { Cache } from 'cache-manager'

interface UserAnswer {
    username: string;
    answers: any
}
@Injectable()
export class AppService {
    constructor(@Inject(CACHE_MANAGER) private readonly cacheManager: Cache ){}

    async saveUserAnswer(userAnswer: UserAnswer){
        await this.cacheManager.set(userAnswer.username,userAnswer.answers,86400)
    }

    async getUserAnswers(username){
        console.log(await this.cacheManager.get(username))
        return await this.cacheManager.get(username)
    }
}
