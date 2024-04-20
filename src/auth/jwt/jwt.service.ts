import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';
import * as jwt from 'jsonwebtoken';
import { APP_CONFIG } from '../../config';

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
      throw new HttpException('jwt invalid', HttpStatus.UNAUTHORIZED);
    }
  }

  /**
   * Access, Refresh Token 발급
   */
  async getToken(user, agent) {
    const access = jwt.sign({ user }, APP_CONFIG.jwtSecret, {
      expiresIn: APP_CONFIG.accessTokenExpires,
    });
    const str = Math.random().toString(36).slice(2, 13);
    const refresh = jwt.sign({ data: str }, APP_CONFIG.jwtSecret, {
      expiresIn: APP_CONFIG.refreshTokenExpires,
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
  async refresh(access: string, refresh: string, agent: string) {
    // 토큰 유무 확인
    if (!(access && refresh)) {
      throw new HttpException("token isn't exist", HttpStatus.UNAUTHORIZED);
    }
    // Refresh Token expired check
    try {
      this.verifyToken(refresh, APP_CONFIG.jwtSecret);
    } catch (e) {
      throw new HttpException('refresh token expired', HttpStatus.UNAUTHORIZED);
    }
    // Token 비교
    const token = await this.prisma.userAccessTokens.findFirst({
      where: {
        access,
        refresh,
      },
    });
    if (!token) {
      throw new HttpException('token not match', HttpStatus.UNAUTHORIZED);
    }
    const payload: any = this.getPayload(access);
    return this.getToken(payload.user, agent);
  }
}
