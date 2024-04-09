import { IsEmail, IsString } from 'class-validator';

export class SignUpDto {
  @IsString()
  readonly displayName: string;

  @IsEmail()
  readonly email: string;

  @IsString()
  password: string;
}
