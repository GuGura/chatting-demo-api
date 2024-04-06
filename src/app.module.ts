import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { SuthService } from './suth/suth.service';

@Module({
  imports: [AuthModule],
  controllers: [AppController],
  providers: [AppService, SuthService],
})
export class AppModule {}
