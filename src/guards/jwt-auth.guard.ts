import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { IS_PUBLIC_KEY } from '../auth/strategy/public.decorator';
import { Reflector } from '@nestjs/core';
import { Request } from 'express';
import { JwtService } from '../auth/jwt.service';
import { jwtConstants } from '../auth/strategy/constants';

@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(
    private reflector: Reflector,
    private jwtService: JwtService,
  ) {}

  canActivate(context: ExecutionContext) {
    // SkipAuthDecoration Check
    const isSkip = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    const request = context.switchToHttp().getRequest<Request>();

    // SkipAuthDecoration 또는 refresh token 요청이면 true
    if (
      isSkip ||
      (request.url === '/auth/refresh' && request.method === 'POST')
    ) {
      console.log(isSkip);
      console.log(request.url === '/auth/refresh' && request.method === 'POST');
      return true;
    }
    // Access Token verify check
    const payload: any = this.validateRequest(request);

    request['user'] = payload?.user;
    return true;
  }

  private validateRequest(request: Request) {
    const access = request.cookies['access'];

    if (!access) {
      throw new UnauthorizedException('token miss');
    }
    return this.jwtService.verifyToken(access, jwtConstants.secret);
  }
}
