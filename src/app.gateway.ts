import {
  WebSocketGateway,
  OnGatewayInit,
  OnGatewayConnection,
  OnGatewayDisconnect,
  WebSocketServer,
} from '@nestjs/websockets';
import { Server, Socket } from 'socket.io';

@WebSocketGateway({ cors: '*' })
export class AppGateway
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
    // console.log('client::', client.handshake);
    // console.log('args::', args);
    client.emit('message', 'test');
  }
}
