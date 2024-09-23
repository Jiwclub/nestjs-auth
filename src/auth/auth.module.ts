import { MiddlewareConsumer, Module, RequestMethod } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
// import { LocalStrategy } from './strategies/local.strategy';
// import { JwtStrategy } from './strategies/jwt.strategy';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { MongooseModule } from '@nestjs/mongoose';
import { User, UserSchema } from 'src/user/schemas/user.schema/user.schema';
import { LocalStrategy } from './strategies/local.strategy/local.strategy';
import { JwtStrategy } from './strategies/jwt.strategy/jwt.strategy';
import { AuthMiddleware } from './middleware/middleware.middleware';
// import { User, UserSchema } from './user.schema';

@Module({
  imports: [
    PassportModule,
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: async (configService: ConfigService) => ({
        secret: configService.get<string>('JWT_SECRET'), // ต้องดึงค่า JWT_SECRET จาก .env
        signOptions: {
          expiresIn: configService.get<string>('JWT_EXPIRATION_TIME') || '15m',
        }, // Default เป็น 15 นาที
      }),
    }),
    MongooseModule.forFeature([{ name: User.name, schema: UserSchema }]),
  ],
  providers: [AuthService, LocalStrategy, JwtStrategy],
  controllers: [AuthController],
})
export class AuthModule {
  configure(consumer: MiddlewareConsumer) {
    consumer
      .apply(AuthMiddleware)
      .forRoutes({ path: 'protected/*', method: RequestMethod.ALL }); // Protect specific routes
  }
}
