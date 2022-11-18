import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { UpdateDto } from './dto/update-question.dto';
import { QuestionInterface, ResponseQuestion } from './question.interface';
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

    async getCorrectRatio(answer: string[]) : Promise<any>{
        let count = 0
        const q = await this.questionModal.find();
        for(let i = 0; i < q.length; i++){
            if(answer[i] === q[i].correctAns){
                count ++;
            }
        }
        return count / q.length
    }


}
