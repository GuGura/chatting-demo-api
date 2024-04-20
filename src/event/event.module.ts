import { Module } from '@nestjs/common';
import { EventController } from './event.controller';
import { EventService } from './event.service';
import { EventGateway } from './event.gateway';

@Module({
  controllers: [EventController],
  providers: [EventService, EventGateway]
})
export class EventModule {}
