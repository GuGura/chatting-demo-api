import {Controller, Get, UseGuards} from '@nestjs/common';
import { AppService } from './app.service';
import { SkipAuthDecorator } from './auth/strategy/public.decorator';
import {JwtAuthGuard} from "./guards/jwt-auth.guard";


@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get()
  @UseGuards(JwtAuthGuard)
  getHello(): string {
    console.log('test');
    return this.appService.getHello();
  }
}
