import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { MongooseModule } from '@nestjs/mongoose';
import { QuestionModule } from 'libs/question/src';
import { UserModule } from 'libs/user/user.module';
import { AuthModule } from 'libs/auth/auth.module';

@Module({
  imports: [
    QuestionModule,
    UserModule,
    AuthModule,
    MongooseModule.forRoot('mongodb://localhost/question-manager'),
    MongooseModule.forRoot('mongodb://localhost/user-manager')],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
