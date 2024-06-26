import {
  CanActivate,
  ExecutionContext,
  HttpException,
  HttpStatus,
  Injectable,
} from '@nestjs/common';
import { IS_PUBLIC_KEY } from '../auth/strategy/public.decorator';
import { Reflector } from '@nestjs/core';
import { Request } from 'express';
import { JwtService } from '../auth/jwt/jwt.service';
import { APP_CONFIG } from '../config';

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
      throw new HttpException('token miss', HttpStatus.UNAUTHORIZED);
    }
    return this.jwtService.verifyToken(access, APP_CONFIG.jwtSecret);
  }
}
