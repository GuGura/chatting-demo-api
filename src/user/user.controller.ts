import {
  Controller,
  Get,
  Post,
  Req,
  UploadedFile,
  UseInterceptors,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import * as multerS3 from 'multer-s3';
import { S3Client } from '@aws-sdk/client-s3';
import { generateFileName } from '../util/generate-string.util';
import { format } from 'date-fns';
import { extname } from 'path';

@Controller('user')
export class UserController {
  @Get('profile')
  getProfile(@Req() req) {
    return req.user;
  }

  @Post('profile')
  @UseInterceptors(
    FileInterceptor('icon', {
      storage: multerS3({
        s3: new S3Client({
          region: 'auto',
          endpoint:
            'https://bcca14eba4f50b2c4cd3f1d2670572d6.r2.cloudflarestorage.com',
          credentials: {
            accessKeyId: '009c5f00eba3a0af3f9d3144d5ec7099',
            secretAccessKey:
              '5564fbd2e93896352b21652cfd81abad4aa79ffa4d30d5cb72bd4421558f0c0e',
          },
        }),
        acl: 'public-read',
        bucket: 'chatting',
        key(req, file, cb) {
          const fileName = generateFileName();
          const date = format(new Date(), 'yyyy-MM').split('-');
          const ext = extname(file.originalname);
          cb(null, `upload/user/${date[0]}/${date[1]}/${fileName}${ext}`);
        },
      }),
      limits: {
        fileSize: 1024 * 1024 * 5,
      },
      fileFilter(req, file, cb) {
        if (
          file.mimetype === 'image/png' ||
          file.mimetype === 'image/jpg' ||
          file.mimetype === 'image/jpeg' ||
          file.mimetype === 'image/svg+xml'
        ) {
          cb(null, true);
        } else {
          cb(new Error('Invalid file type'), false);
        }
      },
    }),
  )
  editProfile(@UploadedFile() file, @Req() req) {
    const iconUrl = file?.key;
    return '';
  }
}
