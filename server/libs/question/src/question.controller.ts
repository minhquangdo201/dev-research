import { Body, Controller, Delete, Get, Param, Post, Put, Req } from "@nestjs/common";
import { UpdateDto } from "./dto/update-question.dto";
import { QuestionInterface } from "./question.interface";
import { QuestionService } from "./question.service";

@Controller('question')
export class QuestionController {
    constructor(private questionService: QuestionService){}

    @Get('current')
    async getCurrentQuestion(): Promise<QuestionInterface>{
        return this.questionService.currentQuestion();
    }
        
    @Get('getAll')
    async getAll(): Promise<QuestionInterface[]>{
        return this.questionService.getAll();
    }

    @Post('releaseQuestion')
    async addQuestion(@Req() req): Promise<QuestionInterface>{
        return this.questionService.addQuestion(req.body);
    }

    @Delete(':id')
    remove(@Param('id') id: string){
        return this.questionService.remove(id);
    }
    
    @Put(':id')
    update(@Param('id') id: string, @Body() updateQuestionDto: UpdateDto){
        return this.questionService.update(id, updateQuestionDto)
    }
}