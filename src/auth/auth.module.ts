import {Module} from '@nestjs/common';
import {AuthController} from './auth.controller';
import {AuthService} from './auth.service';
import {UserModule} from '../user/user.module';
import {PassportModule} from '@nestjs/passport';
import {LocalStrategy} from './strategy/local.strategy';
import {JwtService} from "./jwt.service";

@Module({
    imports: [
        UserModule,
        PassportModule,
    ],
    controllers: [AuthController],
    providers: [AuthService, LocalStrategy, JwtService],
})
export class AuthModule {
}
