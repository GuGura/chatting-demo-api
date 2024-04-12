import {
  ConnectedSocket,
  MessageBody,
  SubscribeMessage,
  WebSocketGateway,
} from '@nestjs/websockets';
import { Socket } from 'socket.io';

@WebSocketGateway({ cors: '*' })
export class EventsGateway {
  @SubscribeMessage('events')
  handleEvent(@MessageBody() data: string): string {
    return data;
  }

  @SubscribeMessage('events')
  handleEvent2(@MessageBody('id') id: number): number {
    // id === messageBody.id
    return id;
  }

  @SubscribeMessage('events')
  handleEvent3(client: Socket, data: string): string {
    return data;
  }

  @SubscribeMessage('events')
  handleEvent4(
    @MessageBody() data: string,
    @ConnectedSocket() client: Socket,
  ): string {
    return data;
  }
}
