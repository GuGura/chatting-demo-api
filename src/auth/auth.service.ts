import { BadRequestException, Injectable } from '@nestjs/common';
import { UserService } from '../user/user.service';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { PrismaService } from '../prisma/prisma.service';
import * as process from 'process';
import { Response } from 'express';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UserService,
    private jwtService: JwtService,
    private prisma: PrismaService,
  ) {}

  async validateUser(email: string, pwd: string): Promise<any> {
    const user = await this.usersService.findLocalUser(email);
    const isCompare = await this.compare(pwd, user.password);

    //TODO: isCompare가 false 일 경우 추후 임시패스워드 로직도 추가해야함
    if (isCompare) {
      return {
        id: user.user.id,
        displayName: user.user.displayName,
        email: user.oauthIdOrEmail,
      };
    }
    return null;
  }

  async login(user, agent) {
    const token = await this.generateToken(user, agent);
    return {
      user,
      access: token.access,
      refresh: token.refresh,
    };
  }

  async register(data: any) {
    const findUser = await this.usersService.findLocalUser(data.email);
    if (findUser) {
      throw new BadRequestException('User alReady Exist!');
    }
    data.password = await this.bcrypt(data.password);
    const { oauthIdOrEmail, user } =
      await this.usersService.createLocalUser(data);
    return {
      id: user.id,
      displayName: user.displayName,
      email: oauthIdOrEmail,
    };
  }

  async bcrypt(password: string) {
    const salt = await bcrypt.genSalt();
    return bcrypt.hash(password, salt);
  }

  async compare(password, hash) {
    return bcrypt.compare(password, hash);
  }

  async generateToken(user, agent) {
    const access = this.jwtService.sign(user);
    const refresh = Math.random().toString(36).slice(2, 13);

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
  async setTokenToHttpOnlyCookie(res: Response, result) {
    const domain = {};
    if (process.env.NODE_ENV === 'production') {
      domain['domain'] = 'test.net';
    }

    res.cookie('access', result.access, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production', //HTTPS 사용여부
      sameSite: 'lax',
      path: '/',
      ...domain,
    });

    res.cookie('refresh', result.refresh, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production', //HTTPS 사용여부
      sameSite: 'lax',
      path: '/auth/refresh',
      ...domain,
    });
  }
}
