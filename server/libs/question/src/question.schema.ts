import { Prop, Schema, SchemaFactory} from '@nestjs/mongoose';
import { Document } from 'mongoose';
import { QuestionInterface, ResponseQuestion } from './question.interface';

@Schema()
export class Question extends Document implements QuestionInterface{
    @Prop({required: true})
    id: String;

    @Prop({required: true})
    question: String;

    @Prop({required: true})
    answers: String[];

    @Prop()
    correctAns?: String;
}


export const QuestionSchema = SchemaFactory.createForClass(Question);