import { Injectable } from '@nestjs/common';
import { AccountType, Provider } from '@prisma/client';
import { PrismaService } from '../prisma/prisma.service';
export type User = any;
@Injectable()
export class UserService {
  constructor(private prisma: PrismaService) {}

  async findByEmail(email: string) {
    const user = await this.prisma.account.findFirst({
      where: {
        type: AccountType.LOCAL,
        provider: Provider.EMAIL,
        oauthIdOrEmail: email,
        user: {
          isDeleted: false,
        },
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

  async mailExists(email: string) {
    const user = await this.prisma.account.findFirst({
      where: {
        type: AccountType.LOCAL,
        provider: Provider.EMAIL,
        oauthIdOrEmail: email,
      },
    });
    return !!user;
  }
  async usernameExists(username: string) {
    const user = await this.prisma.user.findFirst({
      where: {
        username: username,
      },
    });

    return !!user;
  }

  async createLocal(data: any) {
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
