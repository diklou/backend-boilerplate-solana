import httpStatus from 'http-status';
import mongoose from 'mongoose';
import Token from '../token/token.model';
import ApiError from '../errors/ApiError';
import tokenTypes from '../token/token.types';
import { getUserById } from '../user/user.service';
import { IUserDoc, IUserWithTokens } from '../user/user.interfaces';
import { generateAuthTokens, verifyToken } from '../token/token.service';
import { PublicKey } from '@solana/web3.js';
import crypto from 'crypto';
import { User } from '../user';

export const generateNonce = async (address: string) => {
	// check if valid solana address
	if (!(await validateSolanaAddress(address)))
		throw new ApiError(httpStatus.BAD_REQUEST, 'Invalid Address');
	// return nonce
	const nonce = crypto.randomBytes(16).toString('hex');

	await User.findOneAndUpdate({ address }, { nonce }, { upsert: true });

	return nonce;
};

const validateSolanaAddress = async (addr: string) => {
	let publicKey: PublicKey;
	try {
		publicKey = new PublicKey(addr);
		return await PublicKey.isOnCurve(publicKey.toBytes());
	} catch (err) {
		return false;
	}
};
/**
 * Login with username and password
 * @param {string} email
 * @param {string} password
 * @returns {Promise<IUserDoc>}
 */
// export const loginUserWithEmailAndPassword = async (
// 	email: string,
// 	password: string
// ): Promise<IUserDoc> => {
// 	const user = await getUserByEmail(email);
// 	if (!user || !(await user.isNonceMatch(password))) {
// 		throw new ApiError(httpStatus.UNAUTHORIZED, 'Incorrect email or password');
// 	}
// 	return user;
// };

export const login = async (address: string, signature: string): Promise<IUserDoc> => {
	const user = await User.findOne({ address });

	if (!user) {
		throw new ApiError(httpStatus.UNAUTHORIZED, 'Invalid Signature');
	}

	// TODO; verify signature matches nonce.
	if (!(await user.isNonceMatch(signature))) {
		throw new ApiError(httpStatus.UNAUTHORIZED, 'Invalid Signature');
	}

	return user;
};

/**
 * Logout
 * @param {string} refreshToken
 * @returns {Promise<void>}
 */
export const logout = async (refreshToken: string): Promise<void> => {
	const refreshTokenDoc = await Token.findOne({
		token: refreshToken,
		type: tokenTypes.REFRESH,
		blacklisted: false,
	});
	if (!refreshTokenDoc) {
		throw new ApiError(httpStatus.NOT_FOUND, 'Not found');
	}
	await refreshTokenDoc.deleteOne();
};

/**
 * Refresh auth tokens
 * @param {string} refreshToken
 * @returns {Promise<IUserWithTokens>}
 */
export const refreshAuth = async (refreshToken: string): Promise<IUserWithTokens> => {
	try {
		const refreshTokenDoc = await verifyToken(refreshToken, tokenTypes.REFRESH);
		const user = await getUserById(new mongoose.Types.ObjectId(refreshTokenDoc.user));
		if (!user) {
			throw new Error();
		}
		await refreshTokenDoc.deleteOne();
		const tokens = await generateAuthTokens(user);
		return { user, tokens };
	} catch (error) {
		throw new ApiError(httpStatus.UNAUTHORIZED, 'Please authenticate');
	}
};

/**
 * Reset password
 * @param {string} resetPasswordToken
 * @param {string} newPassword
 * @returns {Promise<void>}
 */
// export const resetPassword = async (
// 	resetPasswordToken: any,
// 	newPassword: string
// ): Promise<void> => {
// 	try {
// 		const resetPasswordTokenDoc = await verifyToken(
// 			resetPasswordToken,
// 			tokenTypes.RESET_PASSWORD
// 		);
// 		const user = await getUserById(new mongoose.Types.ObjectId(resetPasswordTokenDoc.user));
// 		if (!user) {
// 			throw new Error();
// 		}
// 		await updateUserById(user.id, { password: newPassword });
// 		await Token.deleteMany({ user: user.id, type: tokenTypes.RESET_PASSWORD });
// 	} catch (error) {
// 		throw new ApiError(httpStatus.UNAUTHORIZED, 'Password reset failed');
// 	}
// };

/**
 * Verify email
 * @param {string} verifyEmailToken
 * @returns {Promise<IUserDoc | null>}
 */
// export const verifyEmail = async (verifyEmailToken: any): Promise<IUserDoc | null> => {
// 	try {
// 		const verifyEmailTokenDoc = await verifyToken(verifyEmailToken, tokenTypes.VERIFY_EMAIL);
// 		const user = await getUserById(new mongoose.Types.ObjectId(verifyEmailTokenDoc.user));
// 		if (!user) {
// 			throw new Error();
// 		}
// 		await Token.deleteMany({ user: user.id, type: tokenTypes.VERIFY_EMAIL });
// 		const updatedUser = await updateUserById(user.id, { isEmailVerified: true });
// 		return updatedUser;
// 	} catch (error) {
// 		throw new ApiError(httpStatus.UNAUTHORIZED, 'Email verification failed');
// 	}
// };
