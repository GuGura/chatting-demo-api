import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { UserService } from '../user/user.service';
import * as bcrypt from 'bcrypt';
import { PrismaService } from '../prisma/prisma.service';
import * as process from 'process';
import { Response } from 'express';
import { SignInDto } from './dto/sign-in.dto';
import { JwtService } from './jwt/jwt.service';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UserService,
    private jwtService: JwtService,
    private prisma: PrismaService,
  ) {}

  async validateUser({ email, password }: SignInDto): Promise<any> {
    //활성화된 로컬유저 유무 체크
    const user = await this.usersService.findByEmail(email);

    // 비밀번호 체크
    const isCompare: boolean = await this.comparePasswords(
      password,
      user?.password,
    );

    //TODO: isCompare가 false 일 경우 추후 임시패스워드 로직도 추가해야함
    if (isCompare) {
      return {
        id: user.user.id,
        username: user.user.username,
        displayName: user.user.displayName,
        email: user.oauthIdOrEmail,
        icon: user.user.icon,
      };
    }
    return null;
  }

  async login(user, agent) {
    const token = await this.jwtService.getToken(user, agent);
    return {
      user,
      access: token.access,
      refresh: token.refresh,
    };
  }

  async register(newUser: any) {
    const mailExists: boolean = await this.usersService.mailExists(
      newUser.email,
    );
    if (mailExists) {
      throw new HttpException('duplicate email', HttpStatus.BAD_REQUEST);
    }

    const usernameExists: boolean = await this.usersService.usernameExists(
      newUser.username,
    );
    if (usernameExists) {
      throw new HttpException('duplicate username', HttpStatus.BAD_REQUEST);
    }

    newUser.password = await this.hashPassword(newUser.password);

    const { oauthIdOrEmail, user } =
      await this.usersService.createLocal(newUser);

    return {
      id: user.id,
      username: user.username,
      displayName: user.displayName,
      email: oauthIdOrEmail,
      icon: user?.icon,
    };
  }

  async setTokenToHttpOnlyCookie(res: Response, result) {
    const domain = {};
    if (process.env.NODE_ENV === 'production') {
      domain['domain'] = 'test.net';
    }

    res.cookie('access', result.access, {
      // httpOnly: true,
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

  removeHttpOnlyCookie(res: Response) {
    const domain = {};
    if (process.env.NODE_ENV === 'production') {
      domain['domain'] = 'test.net';
    }
    res.cookie('access', '', {
      // httpOnly: true,
      expires: new Date(Date.now() - 1000),
      secure: process.env.NODE_ENV === 'production', //HTTPS 사용여부
      sameSite: 'strict',
      ...domain,
    });
    res.cookie('refresh', '', {
      httpOnly: true,
      expires: new Date(Date.now() - 1000),
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      ...domain,
    });
  }

  async signOut(user) {
    this.prisma.user.update({
      where: {
        id: user.id,
      },
      data: {
        isDeleted: true,
        deletedAt: new Date(),
      },
    });
  }

  private async hashPassword(password: string) {
    const salt = await bcrypt.genSalt();
    return bcrypt.hash(password, salt);
  }

  private async comparePasswords(password, hash) {
    if (!hash) return false;
    return bcrypt.compare(password, hash);
  }
}
