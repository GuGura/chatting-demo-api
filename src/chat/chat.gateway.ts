import {
  WebSocketGateway,
  OnGatewayInit,
  OnGatewayConnection,
  OnGatewayDisconnect,
  WebSocketServer, SubscribeMessage, MessageBody,
} from '@nestjs/websockets';
import { Server, Socket } from 'socket.io';

@WebSocketGateway({ cors: '*' , namespace:'chat'})
export class ChatGateway
    implements OnGatewayInit, OnGatewayDisconnect, OnGatewayConnection
{
  @WebSocketServer()
  server: Server;

  afterInit() {
    console.log('Initialized!');
  }

  handleDisconnect(client: Socket): any {
    client.disconnect();
  }

  async handleConnection(client: Socket, ...args: any[]) {
    client.emit('message', 'test');
  }

  @SubscribeMessage('events')
  handleEvent(@MessageBody() data: string): string {
    return data;
  }
}
