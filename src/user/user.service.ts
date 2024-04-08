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

  async findOne(username: string): Promise<User | undefined> {
    return this.users.find((user) => user.username === username);
  }

  async findLocalUser(email: string) {
    return this.prisma.account.findFirst({
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
          },
        },
        password: true,
        oauthIdOrEmail: true,
      },
    });
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
            displayName: data.displayName,
            icon: data?.icon,
          },
        },
      },
      select: {
        oauthIdOrEmail: true,
        user: {
          select: {
            id: true,
            displayName: true,
            icon: true,
          },
        },
      },
    });
  }
}
