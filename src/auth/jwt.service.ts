import {Injectable, UnauthorizedException} from "@nestjs/common";
import {PrismaService} from "../prisma/prisma.service";
import * as jwt from 'jsonwebtoken'
import {jwtConstants} from "./strategy/constants";
@Injectable()
export class JwtService{
    constructor(private prisma:PrismaService) {
    }

    /**
     * return payload
     */
    getPayload(){
    }

    /**
     * 토큰 유효성검사
     */
    verifyToken(tokenString:string, secretKey:string){
        try {
            return jwt.verify(tokenString, secretKey) as (jwt.JwtPayload | string)
        } catch (e) {
            throw new UnauthorizedException();
        }
    }

    /**
     * Access, Refresh Token 발급
     */
    getToken(){

    }


    /**
     * Refresh Token 요청
     */
    refresh(){}

}