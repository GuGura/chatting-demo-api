import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import * as jwt from 'jsonwebtoken';
import { jwtConstants } from './strategy/constants';

@Injectable()
export class JwtService {
  constructor(private prisma: PrismaService) {}

  /**
   * return payload
   */
  getPayload(tokenString: string) {
    return jwt.decode(tokenString);
  }

  /**
   * 토큰 유효성검사
   */
  verifyToken(tokenString: string, secretKey: string) {
    try {
      return jwt.verify(tokenString, secretKey) as jwt.JwtPayload | string;
    } catch (e) {
      throw new UnauthorizedException();
    }
  }

  /**
   * Access, Refresh Token 발급
   */
  async getToken(user, agent) {
    const access = jwt.sign({ user }, jwtConstants.secret, {
      expiresIn: '1m',
    });
    const str = Math.random().toString(36).slice(2, 13);
    const refresh = jwt.sign({ data: str }, jwtConstants.secret, {
      expiresIn: '30d',
    });

    const token = await this.prisma.userAccessTokens.findUnique({
      where: {
        userId_platform: {
          userId: user.id,
          platform: agent,
        },
      },
    });

    if (token) {
      await this.prisma.userAccessTokens.update({
        where: {
          userId_platform: {
            userId: user.id,
            platform: agent,
          },
        },
        data: {
          access,
          refresh,
        },
      });
    } else {
      await this.prisma.userAccessTokens.create({
        data: {
          userId: user.id,
          platform: agent,
          access,
          refresh,
        },
      });
    }

    return {
      access,
      refresh,
    };
  }

  /**
   * Refresh Token 요청
   */
  refresh() {}
}
