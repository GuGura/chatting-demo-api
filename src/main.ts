import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import helmet from 'helmet';
import * as cookieParser from 'cookie-parser';
import { ValidationPipe } from '@nestjs/common';
import { json, urlencoded } from 'body-parser';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.use(helmet());
  app.useGlobalPipes(new ValidationPipe());
  app.use(json({ limit: '100mb' }));
  app.use(urlencoded({ limit: '100mb', extended: true }));
  app.use(cookieParser());
  app.enableCors({
    origin: /^(https?:\/\/)?(localhost|.*test\.net)(:[0-9]+)?$/,
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    credentials: true,
  });
  await app.listen(3500);
}

bootstrap();
