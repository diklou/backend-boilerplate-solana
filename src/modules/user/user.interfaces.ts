import { Model, Document } from 'mongoose';
import { AccessAndRefreshTokens } from '../token/token.interfaces';

export interface IUser {
  address: string;
  nonce: string;
  role: string;
}

export interface IUserDoc extends IUser, Document {
  isNonceMatch(signature: string): Promise<boolean>;
}

export interface IUserModel extends Model<IUserDoc> {
}

export type UpdateUserBody = Partial<IUser>;

export type NewRegisteredUser = Omit<IUser, 'role' | 'isEmailVerified'>;

export type NewCreatedUser = Omit<IUser, 'isEmailVerified'>;

export interface IUserWithTokens {
  user: IUserDoc;
  tokens: AccessAndRefreshTokens;
}
