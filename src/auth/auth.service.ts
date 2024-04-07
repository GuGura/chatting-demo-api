import { BadRequestException, Injectable } from '@nestjs/common';
import { UserService } from '../user/user.service';
import { JwtService } from '@nestjs/jwt';
import { RegisterDto } from './dto/register.dto';
import * as bcrypt from 'bcrypt';
import { PrismaService } from '../prisma/prisma.service';
import { AccountType, Provider } from '@prisma/client';
import { LoginDto } from './dto/login.dto';

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
    if (user && isCompare) {
      const { password, ...result } = user;
      return result;
    }
    return null;
  }

  async login(user: LoginDto) {
    const payload = { username: user.email, sub: user.password };
    return {
      access_token: this.jwtService.sign(payload),
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
}
