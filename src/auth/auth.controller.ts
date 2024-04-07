import { Controller, Get, Post, Req, UseGuards } from '@nestjs/common';
import { LocalAuthGuard } from './strategy/local.strategy';
import { AuthService } from './auth.service';
import { Public } from './strategy/public.decorator';

@Public()
@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}
  @UseGuards(LocalAuthGuard)
  @Post('sign-in')
  async login(@Req() req) {
    return this.authService.login(req.user);
  }

  @Post('sign-up')
  async register() {}
}
