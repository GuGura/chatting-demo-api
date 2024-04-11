import { Injectable } from '@nestjs/common';
import { AccountType, Provider } from '@prisma/client';
import { PrismaService } from '../prisma/prisma.service';
export type User = any;
@Injectable()
export class UserService {
  constructor(private prisma: PrismaService) {}
  private readonly users = [
    {
      userId: 1,
      username: 'john',
      password: 'changeme',
    },
    {
      userId: 2,
      username: 'maria',
      password: 'guess',
    },
  ];

  async findLocalUserByEmail(email: string) {
    const user = await this.prisma.account.findFirst({
      where: {
        type: AccountType.LOCAL,
        provider: Provider.EMAIL,
        oauthIdOrEmail: email,
      },
      select: {
        user: {
          select: {
            id: true,
            displayName: true,
            icon: true,
            username: true,
          },
        },
        password: true,
        oauthIdOrEmail: true,
      },
    });
    if (!user) {
      return null;
    }
    return user;
  }

  async findLocalUserByUsername(username: string) {
    const user = await this.prisma.user.findFirst({
      where: {
        username: username,
      },
      select: {
        id: true,
        displayName: true,
        icon: true,
        username: true,
      },
    });
    if (!user) {
      return null;
    }
    return user;
  }

  async createLocalUser(data: any) {
    return this.prisma.account.create({
      data: {
        type: AccountType.LOCAL,
        provider: Provider.EMAIL,
        oauthIdOrEmail: data.email,
        password: data.password,
        user: {
          create: {
            username: data.username,
          },
        },
      },
      select: {
        oauthIdOrEmail: true,
        user: {
          select: {
            id: true,
            username: true,
            displayName: true,
            icon: true,
          },
        },
      },
    });
  }
}
