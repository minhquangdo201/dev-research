import { Module, CacheModule } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { MongooseModule } from '@nestjs/mongoose';
import { QuestionModule } from 'libs/question/src';
import { UserModule } from 'libs/user/user.module';
import { AuthModule } from 'libs/auth/auth.module';
import * as redisStore from 'cache-manager-redis-store';


@Module({
  imports: [
    QuestionModule,
    UserModule,
    AuthModule,
    MongooseModule.forRoot('mongodb://localhost/question-manager'),
    CacheModule.register({
      store: redisStore as any,
      host: 'localhost',
      port: 6379,
      ttl: 86400
    })
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
