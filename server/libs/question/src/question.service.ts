import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { UpdateDto } from './dto/update-question.dto';
import { ListAnswers, QuestionInterface, ResponseQuestion } from './question.interface';
import { Question } from './question.schema';


@Injectable()
export class QuestionService {
    constructor(
        @InjectModel(Question.name) private questionModal: Model<Question>
    ) { }

    async addQuestion(question: QuestionInterface): Promise<QuestionInterface> {
        const q = new this.questionModal(question);
        return q.save();
    }

    async getAll(): Promise<ResponseQuestion[]> {
        return this.questionModal.find({},{ correctAns: 0})
    }

    async remove(id: string) {
        return this.questionModal.findByIdAndRemove(id);
    }

    async update(id: string, updateQuestionDto: UpdateDto): Promise<QuestionInterface> {
        return this.questionModal.findByIdAndUpdate(id, updateQuestionDto);
    }

    async getCorrectRatio(req: ListAnswers) : Promise<any>{
        let count = 0
        let answers = req.answers;
        const totalQues = await this.questionModal.countDocuments()
        for(let i = 0; i < answers.length; i++){
            const question = await this.questionModal.findOne({id: answers[i].id});
            if(!question) {
                continue
            }
            if(question.correctAns === answers[i].answer){
                count ++
            }
        }
        
        return count / totalQues;
    }


}
