import {
  Injectable,
  NestMiddleware,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Request, Response, NextFunction } from 'express';
import { AuthService } from '../auth.service';
// import { AuthService } from './auth.service';

@Injectable()
export class AuthMiddleware implements NestMiddleware {
  constructor(
    private jwtService: JwtService,
    private authService: AuthService, // ใช้ AuthService ในการรีเฟรช token
  ) {}

  async use(req: Request, res: Response, next: NextFunction) {
    try {
      const authHeader = req.headers['authorization'];
      if (!authHeader) {
        throw new UnauthorizedException('Authorization header is missing');
      }

      const token = authHeader.split(' ')[1];
      if (!token) {
        throw new UnauthorizedException('Access token is missing');
      }

      // ตรวจสอบ Access Token
      const payload = this.jwtService.verify(token, {
        secret: process.env.JWT_SECRET,
      });

      // ถ้า Access Token ถูกต้อง ดำเนินการต่อ
      req['user'] = payload; // ดึงข้อมูลผู้ใช้จาก token และเก็บใน req
      next();
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        // ถ้า Access Token หมดอายุ, ทำการรีเฟรช token
        const refreshToken = req.headers['x-refresh-token'] as string; // สมมุติว่า refresh token อยู่ใน header
        if (!refreshToken) {
          throw new UnauthorizedException('Refresh token is missing');
        }

        try {
          // ทำการรีเฟรช Access Token ด้วย AuthService
          const newTokens = await this.authService.refreshTokens(
            req['user'].sub,
            refreshToken,
          );

          // เพิ่ม Access Token ใหม่ใน response header
          res.setHeader('Authorization', `Bearer ${newTokens.accessToken}`);
          req['user'] = this.jwtService.verify(newTokens.accessToken); // อัปเดตข้อมูลผู้ใช้ใน req

          next(); // ดำเนินการต่อ
        } catch (err) {
          throw new UnauthorizedException('Invalid refresh token');
        }
      } else {
        throw new UnauthorizedException('Invalid access token');
      }
    }
  }
}
