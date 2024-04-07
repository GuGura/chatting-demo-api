import { IsEmail, IsString } from 'class-validator';

export class RegisterDto {
  @IsString()
  readonly displayName: string;

  @IsEmail()
  readonly email: string;

  @IsString()
  password: string;
}
