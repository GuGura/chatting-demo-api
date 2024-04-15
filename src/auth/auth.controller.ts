import { Body, Controller, Post, Req, Res, UseGuards } from '@nestjs/common';
import { LocalAuthGuard } from './strategy/local.strategy';
import { AuthService } from './auth.service';
import { SkipAuthDecorator } from './strategy/public.decorator';
import { SignUpDto } from './dto/sign-up.dto';

@SkipAuthDecorator()
@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}
  @UseGuards(LocalAuthGuard)
  @Post('sign-in')
  async signIn(@Req() req, @Res() res) {
    const result = await this.authService.login(
      req.user,
      req.headers['user-agent'],
    );
    await this.authService.setTokenToHttpOnlyCookie(res, result);
    res.send(result.user);
  }

  @Post('sign-up')
  async signUp(@Body() dto: SignUpDto, @Req() req, @Res() res) {
    const newUser = await this.authService.register(dto);
    const result = await this.authService.login(
      newUser,
      req.headers['user-agent'],
    );
    await this.authService.setTokenToHttpOnlyCookie(res, result);
    res.send(result.user);
  }

  @Post('logout')
  async logout(@Res() res) {
    this.authService.logoutHttpOnlyCookie(res);
    res.send({
      message: 'logout',
    });
  }

  @SkipAuthDecorator()
  @Post('refresh')
  async refresh(@Req() req, @Res() res: Response) {
    const result = await this.authService.refresh(
      req.cookie['access'],
      req.cookie['refresh'],
      req.headers['user-agent'],
    );
  }
}
