import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { UpdateDto } from './dto/update-question.dto';
import { QuestionInterface } from './question.interface';
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

    async currentQuestion(): Promise<QuestionInterface> {
        return this.questionModal.findOne({});
    }

    async getAll(): Promise<QuestionInterface[]>{
        return this.questionModal.find().exec();
    }

    async remove(id: string) {
        return this.questionModal.findByIdAndRemove(id);
    }

    async update(id: string, updateQuestionDto: UpdateDto): Promise<QuestionInterface> {
        return this.questionModal.findByIdAndUpdate(id, updateQuestionDto);
    }



}
