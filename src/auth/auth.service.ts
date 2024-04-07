import { BadRequestException, Injectable } from '@nestjs/common';
import { UserService } from '../user/user.service';
import { JwtService } from '@nestjs/jwt';
import { RegisterDto } from './dto/register.dto';
import * as bcrypt from 'bcrypt';
import { PrismaService } from '../prisma/prisma.service';
import { AccountType, Provider } from '@prisma/client';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UserService,
    private jwtService: JwtService,
    private prisma: PrismaService,
  ) {}

  async validateUser(username: string, pass: string): Promise<any> {
    const user = await this.usersService.findOne(username);
    if (user && user.password === pass) {
      const { password, ...result } = user;
      return result;
    }
    return null;
  }
  async login(user: any) {
    const payload = { username: user.username, sub: user.userId };
    return {
      access_token: this.jwtService.sign(payload),
    };
  }

  async register(data: any) {
    const findUser = await this.prisma.account.findFirst({
      where: {
        type: AccountType.LOCAL,
        provider: Provider.EMAIL,
        oauthIdOrEmail: data.email,
      },
    });
    if (findUser) {
      throw new BadRequestException('User alReady Exist!');
    }
    data.password = await this.bcrypt(data.password);
    return this.prisma.user.create({
      data: {
        displayName: data.displayName,
        icon: data?.icon,
        Account: {
          create: {
            type: AccountType.LOCAL,
            provider: Provider.EMAIL,
            oauthIdOrEmail: data.email,
            password: data.password,
          },
        },
      },
      select: {
        id: true,
        displayName: true,
        Account: {
          select: {
            oauthIdOrEmail: true,
          },
        },
      },
    });
  }

  async bcrypt(password: string) {
    const salt = await bcrypt.genSalt();
    return bcrypt.hash(password, salt);
  }
}
