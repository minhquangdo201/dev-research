import { QuestionService } from '@app/question';
import { CACHE_MANAGER, Inject, Injectable } from '@nestjs/common';
import { Cache } from 'cache-manager'

interface UserAnswer {
    username: string;
    answers: Answers[]
}
interface ResponseAnswer {
    answers: Answers[]
}

interface Answers {
    id: string,
    answer: string
}

interface ResponseQuestion {
    id: String;
    question: String;
    answers: String[];
    answered: String
}
@Injectable()
export class AppService {
    constructor(@Inject(CACHE_MANAGER) private readonly cacheManager: Cache ,private questionService: QuestionService){}

    async saveUserAnswer(userAnswer: UserAnswer){
        await this.cacheManager.set(userAnswer.username,userAnswer.answers,86400)
    }

    async getUserAnswers(username){
        const res:ResponseAnswer = await this.cacheManager.get(username)
        const question = await this.questionService.getAll()
        const resQuestion: ResponseQuestion[] = []
        if(res){
            for(let i = 0; i < question.length; i++){
                resQuestion[i] = {...resQuestion[i], id: question[i].id, question: question[i].question, answers: question[i].answers, answered:''}
                for(let j = 0; j < res.answers.length; j++){
                    if(question[i].id === res.answers[j].id){
                        resQuestion[i] = {...resQuestion[i], answered: res.answers[j].answer}
                    }
                }
            }
        }
        console.log(resQuestion)
        return resQuestion;
    }
}
