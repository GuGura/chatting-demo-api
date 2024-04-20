import {
  WebSocketGateway,
  OnGatewayInit,
  OnGatewayConnection,
  OnGatewayDisconnect,
  WebSocketServer,
  SubscribeMessage,
  MessageBody,
  ConnectedSocket,
} from '@nestjs/websockets';
import { Server, Socket } from 'socket.io';
import { Logger, UnauthorizedException } from '@nestjs/common';

@WebSocketGateway({ cors: '*' })
export class EventGateway
  implements OnGatewayInit, OnGatewayDisconnect, OnGatewayConnection
{
  @WebSocketServer()
  server: Server;

  private logger = new Logger('chat');

  constructor() {
    this.logger.log('constructor');
  }

  afterInit() {
    this.logger.log('Initialized!');
  }

  handleDisconnect(socket: Socket): any {
    this.logger.log('disconnect!');
    socket.emit('Error', new UnauthorizedException());
    socket.disconnect();
  }

  async handleConnection(@ConnectedSocket() socket: Socket, ...args: any[]) {
    this.logger.log(`connected : ${socket.id} ${socket.nsp.name}`);
  }

  @SubscribeMessage('new_user')
  handleNewUser(
    @MessageBody() dto: { message: string; user: string },
    @ConnectedSocket() socket: Socket,
  ) {
    console.log(socket.id);
    socket.broadcast.emit('user_connected', dto);
    return dto;
  }
}
