import { IsEmail, IsString } from 'class-validator';

export class SignUpDto {
  @IsString()
  readonly username: string;

  @IsEmail()
  readonly email: string;

  @IsString()
  password: string;

  displayName: string;
}
