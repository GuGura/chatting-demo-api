import {
  Body,
  Controller,
  Post,
  Req,
  Res,
  UploadedFile,
  UseGuards,
  UseInterceptors,
} from '@nestjs/common';
import * as multerS3 from 'multer-s3';
import { LocalAuthGuard } from './strategy/local.strategy';
import { AuthService } from './auth.service';
import { Public } from './strategy/public.decorator';
import { RegisterDto } from './dto/register.dto';
import { FileInterceptor } from '@nestjs/platform-express';
import { S3Client } from '@aws-sdk/client-s3';
import { generateFileName } from '../util/generate-string.util';
import { format } from 'date-fns';
import { extname } from 'path';

@Public()
@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}
  @UseGuards(LocalAuthGuard)
  @Post('sign-in')
  async login(@Req() req, @Res() res) {
    const result = await this.authService.login(
      req.user,
      req.headers['user-agent'],
    );
    await this.authService.setTokenToHttpOnlyCookie(res, result);
    res.send(result.user);
  }

  @Post('sign-up')
  async register(@Body() dto: RegisterDto, @Req() req, @Res() res) {
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
}
