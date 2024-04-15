import { Controller, Get } from '@nestjs/common';
import { AppService } from './app.service';
import { SkipAuthDecorator } from './auth/strategy/public.decorator';

@SkipAuthDecorator()
@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get()
  getHello(): string {
    console.log('test');
    return this.appService.getHello();
  }
}
