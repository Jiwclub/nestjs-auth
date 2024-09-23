import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { MongooseModule } from '@nestjs/mongoose';
import { AuthModule } from './auth/auth.module';
import { UserModule } from './user/user.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true, // ทำให้ ConfigModule สามารถใช้งานได้ทั่วทั้งแอป
    }),
    MongooseModule.forRoot(process.env.MONGO_URI), // ใช้ค่า Mongo URI จาก .env
    AuthModule,
    UserModule,
  ],
})
export class AppModule {}
