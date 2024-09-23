import { Controller, Post, Body, UseGuards, Request } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignUpDto } from 'src/user/dto/signup.dto/signup.dto';
import { LocalAuthGuard } from './guards/local-auth.guard/local-auth.guard';
import { JwtAuthGuard } from './guards/jwt-auth.guard/jwt-auth.guard';
// import { SignUpDto } from './dto/signup.dto';
// import { LoginDto } from './dto/login.dto';
// import { LocalAuthGuard } from './guards/local-auth.guard';
// import { JwtAuthGuard } from './guards/jwt-auth.guard';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('signup')
  async signUp(@Body() signUpDto: SignUpDto) {
    return this.authService.signUp(signUpDto);
  }

  @UseGuards(LocalAuthGuard)
  @Post('login')
  async login(@Request() req) {
    return this.authService.login(req.user);
  }

  @UseGuards(JwtAuthGuard)
  @Post('refresh')
  async refresh(@Request() req) {
    const userId = req.user.userId;
    const refreshToken = req.headers['authorization'].split(' ')[1]; // Extract refresh token from header
    return this.authService.refreshTokens(userId, refreshToken);
  }

  @UseGuards(JwtAuthGuard)
  @Post('logout')
  async logout(@Request() req) {
    return this.authService.logout(req.user.userId);
  }
}
