import { Controller, Get, Req } from '@nestjs/common';

@Controller('user')
export class UserController {
  @Get('profile')
  getProfile(@Req() req) {
    return req.user;
  }
}
